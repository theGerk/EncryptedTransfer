using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Gerk.BinaryExtension;
using Gerk.LinqExtensions;


namespace Gerk.Crypto.EncryptedTransfer
{
	/// <summary>
	/// A <see cref="Stream"/> for end to end encrypted and secure transfering of data. Data is only written to the underlying stream in blocks. You can complete a block that needs to be written by using <see cref="FlushWriter"/>. When reading, wherever you expect a block to be completed by a <see cref="FlushWriter"/> you should call <see cref="FlushReader"/> to jump to the end of the block. Wrapping this stream with a <see cref="StreamReader"/> or <see cref="StreamWriter"/> is not currently supported. Rather you are encouraged to use a <see cref="BinaryReader"/> and <see cref="BinaryWriter"/>.
	/// </summary>
	public class Tunnel : Stream
	{
		#region Create overloads
		/// <summary>
		/// Initiates handshake to setup secure connection over <see cref="Stream"/>.
		/// </summary>
		/// <typeparam name="T">Identity type.</typeparam>
		/// <param name="stream">The underlying stream. Usually expected to be a network stream.</param>
		/// <param name="localPrivateKey">The private key you use to connect.</param>
		/// <param name="remoteIds">Identifies the public keys that are allowed, encoded as Csp blobs. Can be left <see langword="null"/> to allow connection to anyone. Key can also be found later using <see cref="RemotePublicKey"/> property.</param>
		/// <param name="remoteIdentity">The element of <paramref name="remoteIds"/> that matched the remote's public key. If there was an error or <paramref name="remoteIds"/> was <see langword="null"/> this may be left default.</param>
		/// <param name="error">An error message for if something goes wrong.</param>
		/// <param name="leaveOpen">True to not close the underlying stream when the <see cref="Tunnel"/> is closed.</param>
		/// <returns>The new stream that wraps <paramref name="stream"/> with end to end encyption.</returns>
		public static Tunnel Create<T>(
			Stream stream
			, RSACryptoServiceProvider localPrivateKey
			, IEnumerable<T> remoteIds
			, out T remoteIdentity
			, out TunnelCreationError error
			, out string errorMessage
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, bool leaveOpen = false
#endif
		) where T : IHasPublicKeySha => Create(
			stream
			, localPrivateKey
			, remoteIds
			, x => x.GetPublicKeySha()
			, out remoteIdentity
			, out error
			, out errorMessage
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, leaveOpen
#endif
		);

		/// <summary>
		/// Initiates handshake to setup secure connection over <see cref="Stream"/>.
		/// </summary>
		/// <param name="stream">The underlying stream. Usually expected to be a network stream.</param>
		/// <param name="localPrivateKey">The private key you use to connect.</param>
		/// <param name="remotePublicKeyHashes">The SHA256 hashes of the public keys (encoded as Csp blobs) that are allowed. Can be left <see langword="null"/> to allow connection to anyone. Key can also be found later using <see cref="RemotePublicKey"/> property (this is the original, not the hash).</param>
		/// <param name="remotePublicKeyHash">The element of <paramref name="remotePublicKeyHashes"/> that matched the remote's public key. If there was an error or <paramref name="remotePublicKeyHashes"/> was <see langword="null"/> this may be left default.</param>
		/// <param name="error">An error message for if something goes wrong.</param>
		/// <param name="leaveOpen">True to not close the underlying stream when the <see cref="Tunnel"/> is closed.</param>
		/// <returns>The new stream that wraps <paramref name="stream"/> with end to end encyption.</returns>
		public static Tunnel Create(
			Stream stream
			, RSACryptoServiceProvider localPrivateKey
			, IEnumerable<byte[]> remotePublicKeyHashes
			, out byte[] remotePublicKeyHash
			, out TunnelCreationError error
			, out string errorMessage
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, bool leaveOpen = false
#endif
		) => Create(
			stream
			, localPrivateKey
			, remotePublicKeyHashes
			, x => x
			, out remotePublicKeyHash
			, out error
			, out errorMessage
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, leaveOpen
#endif
		);
		#endregion

		// All sizes below are listed in bytes.
		/// <summary>
		/// Size of the challenge message in bytes to initiate connection.
		/// </summary>
		private const bool USE_OAEP_PADDING = true;
		private const uint AES_KEY_LENGTH = 32; // 256 bit key
		private const uint AES_IV_LENGTH = 16;  // Part of AES definition
		private const uint AES_BLOCK_SIZE = 16; // Part of AES definition
		private const uint MAX_BUFFER_SIZE = 64 << 10; // 64 kiliobytes
		private static readonly int VERSION_NUMBER = Assembly.GetCallingAssembly().GetName().Version.Major;

		// Crypto streams to read and write
		private CryptoStream readStream;
		private CryptoStream writeStream;
		private readonly Stream underlyingStream;

		/// <summary>
		/// Total number of bytes read so far. Really only maters that it is correct mod <see cref="BlockSize"/>.
		/// </summary>
		private ulong bytesRead = 0;
		/// <summary>
		/// Total number of bytes written so far. Really only maters that it is correct mod <see cref="BlockSize"/>.
		/// </summary>
		private ulong bytesWritten = 0;

		/// <summary>
		/// The size in bytes of each block. 
		/// </summary>
		public static uint BlockSize => AES_BLOCK_SIZE;

#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
		/// <summary>
		/// Should <see cref="underlyingStream"/> be disposed by this stream.
		/// </summary>
		private readonly bool leaveOpen;
#endif

		#region CreateHelpers
		private static int ReadAndWriteVersion(BinaryWriter writer, BinaryReader reader)
		{
			writer.Write(VERSION_NUMBER);
			return reader.ReadInt32();
		}


		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="stream">The underlying stream.</param>
		/// <param name="leaveOpen">Whether to leave open or not.</param>
		private Tunnel(
			Stream stream
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, bool leaveOpen = false
#endif
		)
		{
			underlyingStream = stream;
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			this.leaveOpen = leaveOpen;
#endif
		}


		/// <summary>
		/// Creates <see cref="CryptoStream"/>s.
		/// </summary>
		/// <param name="sharedKey">The initialized AES key.</param>
		private void InitCryptoStreams(Aes sharedKey)
		{
			var dec = sharedKey.CreateDecryptor();
			var enc = sharedKey.CreateEncryptor();

			CryptoStream makeCryptoStream(ICryptoTransform crypto, CryptoStreamMode csm) => new CryptoStream(
					underlyingStream
					, crypto
					, csm
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
					, leaveOpen
#endif
				);
			readStream = makeCryptoStream(dec, CryptoStreamMode.Read);
			writeStream = makeCryptoStream(enc, CryptoStreamMode.Write);
		}

		/// <summary>
		/// Reads an AES key from <paramref name="bw"/> that was encrypted with <paramref name="rsa"/>.
		/// </summary>
		/// <param name="bw"></param>
		/// <param name="rsa"></param>
		/// <returns>The AES key</returns>
		private static bool XorAgainstAESKeyFromStream(BinaryReader bw, RSACryptoServiceProvider rsa, Aes aes, out byte[] otherAesKey)
		{
			var success = bw.TryReadBinaryData(out var encryptedAesKey, (int)MAX_BUFFER_SIZE);
			if (success)
			{
				using (var memStream = new MemoryStream(rsa.Decrypt(encryptedAesKey, USE_OAEP_PADDING)))
				using (var reader = new BinaryReader(memStream))
				{
					var key = aes.Key;
					otherAesKey = reader.ReadBytes((int)AES_KEY_LENGTH);
					key.xor(otherAesKey);
					aes.Key = key;

					var iv = aes.IV;
					iv.xor(reader.ReadBytes((int)AES_IV_LENGTH));
					aes.IV = iv;
				}
				return true;
			}
			else
			{
				otherAesKey = null;
				return false;
			}
		}

		/// <summary>
		/// Encrypts the AES key <paramref name="aes"/> with RSA key <paramref name="rsa"/> and write to binary writer <paramref name="bw"/>.
		/// </summary>
		/// <param name="aes"></param>
		/// <param name="bw"></param>
		/// <param name="rsa"></param>
		private static void WriteAesKey(Aes aes, BinaryWriter bw, RSACryptoServiceProvider rsa)
		{
			using (var memStream = new MemoryStream())
			{
				memStream.Write(aes.Key, 0, (int)AES_KEY_LENGTH);
				memStream.Write(aes.IV, 0, (int)AES_IV_LENGTH);
				bw.WriteBinaryData(rsa.Encrypt(memStream.ToArray(), USE_OAEP_PADDING));
			}
		}

		/// <summary>
		/// Sets up an AES key without initializing it.
		/// </summary>
		/// <returns></returns>
		private static Aes aeskey()
		{
			var output = Aes.Create();
			output.Mode = CipherMode.CBC;
			output.Padding = PaddingMode.None;
			return output;
		}
		#endregion

		#region Create
		/// <summary>
		/// Initiates symetric handshake to setup secure connection over <see cref="Stream"/>.
		/// </summary>
		/// <param name="stream">The underlying stream. Usually expected to be a network stream.</param>
		/// <param name="localPrivateKey">The private key you use to connect.</param>
		/// <param name="remoteIds">A collection of remote Ids that are acceptable. Can be left <see langword="null"/> to ingore verification.</param>
		/// <param name="publicKeyShaExtractor">A function that gets the SHA256 hash of a public key encoded as a CspBlob from elements of <paramref name="remoteIds"/>.</param>
		/// <param name="remoteIdentity">The element of <paramref name="remoteIds"/> that matched the remote's public key. If there was an error or <paramref name="remoteIds"/> was <see langword="null"/> this may be left default.</param>
		/// <param name="error">An error message for if something goes wrong.</param>
		/// <param name="leaveOpen">True to not close the underlying stream when the <see cref="Tunnel"/> is closed.</param>
		/// <returns>The new stream that wraps <paramref name="stream"/> with end to end encyption.</returns>
		public static Tunnel Create<Id>(
			Stream stream
			, RSACryptoServiceProvider localPrivateKey
			, IEnumerable<Id> remoteIds
			, Func<Id, byte[]> publicKeyShaExtractor
			, out Id remoteIdentity
			, out TunnelCreationError error
			, out string errorMessage
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, bool leaveOpen = false
#endif
		)
		{
			var output = new Tunnel(
				stream
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
				, leaveOpen
#endif
			);

			try
			{
				using (var hash = SHA256.Create())
				{
					byte[] othersAesKey;
					byte[] myAesKey;
					using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
					using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
					{
						// write some metadata
						var remoteVersion = ReadAndWriteVersion(writer, reader);
						if (remoteVersion != VERSION_NUMBER)
						{
							output.Dispose();
							error = TunnelCreationError.VersionMismatch;
							errorMessage = $"My version: {VERSION_NUMBER}. Remote version: {remoteVersion}.";
							remoteIdentity = default;
							return null;
						}

						// write public key
						writer.WriteBinaryData(localPrivateKey.ExportCspBlob(false));

						// read public key
						if (!reader.TryReadBinaryData(out var remotePublicKeyCspBlob, (int)MAX_BUFFER_SIZE))
						{
							output.Dispose();
							error = TunnelCreationError.LargeBinaryBlock;
							errorMessage = $"Refusing to read public key was larger than max size of {MAX_BUFFER_SIZE} bytes.";
							remoteIdentity = default;
							return null;
						}

						if (remoteIds != null)
						{
							var remotePublicKeySha = hash.ComputeHash(remotePublicKeyCspBlob);

							if (remoteIds.TryFirst(x => publicKeyShaExtractor(x).SequenceEquals(remotePublicKeySha), out var id))
							{
								remoteIdentity = id;
							}
							else
							{
								output.Dispose();
								error = TunnelCreationError.RemoteDoesNotHaveValidPublicKey;
								errorMessage = "Remote's public key is not one of the valid keys passed in.";
								remoteIdentity = default;
								return null;
							}
						}
						else
							remoteIdentity = default;

						// write encrypted AES key
						using (var sharedKey = aeskey())
						{
							sharedKey.GenerateKey();
							sharedKey.GenerateIV();
							myAesKey = sharedKey.Key;

							using (var remotePublicKey = new RSACryptoServiceProvider())
							{
								remotePublicKey.ImportCspBlob(remotePublicKeyCspBlob);
								WriteAesKey(sharedKey, writer, remotePublicKey);
							}

							// read encrypted AES key
							if (!XorAgainstAESKeyFromStream(reader, localPrivateKey, sharedKey, out othersAesKey))
							{
								output.Dispose();
								error = TunnelCreationError.LargeBinaryBlock;
								errorMessage = $"Refusing to read encrypted AES key larger than {MAX_BUFFER_SIZE} bytes.";
								return null;
							}

							output.InitCryptoStreams(sharedKey);
						}
					}

					// From here on in everything is encrypted with AES key
					using (var writer = new BinaryWriter(output, Encoding.UTF8, true))
					using (var reader = new BinaryReader(output, Encoding.UTF8, true))
					{
						// write first block of AES key as a proof that we read it.
						// theoretically we could write anything here to prove it, but if we just did a block of zeros those could be replayed at us, this forces some asymetry so that an attacker can't replay their message at us.
						writer.Write(othersAesKey, 0, (int)AES_BLOCK_SIZE);

						// read remote aes key
						if (BinaryHelpers.memcmp(myAesKey, reader.ReadBytes((int)AES_BLOCK_SIZE), (UIntPtr)AES_BLOCK_SIZE) != 0)
						{
							output.Dispose();
							error = TunnelCreationError.RemoteFailedToVierfyItself;
							errorMessage = "Remote failed to prove its identity.";
							return null;
						}
					}

					error = TunnelCreationError.NoError;
					errorMessage = null;
					return output;
				}
			}
			catch
			{
				output.Dispose();
				throw;
			}
		}
		#endregion

		/// <inheritdoc/>
		public override bool CanRead => true;
		/// <inheritdoc/>
		public override bool CanSeek => false;
		/// <inheritdoc/>
		public override bool CanWrite => true;
		/// <summary>
		/// Not supported
		/// </summary>
		public override long Length => throw new NotSupportedException();
		/// <summary>
		/// Not supported
		/// </summary>
		public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
		/// <summary>
		/// Flushes the underlying stream. Does not call <see cref="FlushReader"/> or <see cref="FlushWriter"/>.
		/// </summary>
		public override void Flush() => underlyingStream.Flush();


		private byte[] writeBuff = new byte[BlockSize];
		/// <summary>
		/// Writes 0s to the stream until the end the current block so it can be sent.
		/// </summary>
		public virtual void FlushWriter()
		{
			var bytesToWrite = bytesWritten % BlockSize;
			if (bytesToWrite != 0)
			{
				bytesToWrite = BlockSize - bytesToWrite;
				Write(writeBuff, 0, (int)bytesToWrite);
			}
		}

		private byte[] readBuff = new byte[BlockSize];
		/// <summary>
		/// Skips to the end of the current block. Meant to skip the 0s wrote by <see cref="FlushWriter"/>.
		/// </summary>
		public virtual void FlushReader()
		{
			var bytesToRead = bytesRead % BlockSize;
			if (bytesToRead != 0)
			{
				bytesToRead = BlockSize - bytesToRead;
				Read(readBuff, 0, (int)bytesToRead);
			}
		}

		/// <inheritdoc/>
		public override int Read(byte[] buffer, int offset, int count)
		{
			var read = readStream.Read(buffer, offset, count);
			bytesRead += (ulong)read;
			return read;
		}
		/// <inheritdoc/>
		public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
		/// <inheritdoc/>
		public override void SetLength(long value) => throw new NotSupportedException();
		/// <inheritdoc/>
		public override void Write(byte[] buffer, int offset, int count)
		{
			bytesWritten += (ulong)count;
			writeStream.Write(buffer, offset, count);
		}

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP3_0_OR_GREATER
		/// <inheritdoc/>
		public override async ValueTask DisposeAsync()
		{
			if (writeStream != null)
				FlushWriter();
			var a = writeStream.DisposeAsync();
			var b = readStream.DisposeAsync();
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			if (!leaveOpen)
#endif
				await underlyingStream.DisposeAsync();

			await a;
			await b;
		}
#endif
		/// <inheritdoc/>
		public override void Close()
		{
			if (writeStream != null)
				FlushWriter();
			writeStream?.Close();
			readStream?.Close();
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			if (!leaveOpen)
#endif
				underlyingStream?.Close();
		}
	}
}
