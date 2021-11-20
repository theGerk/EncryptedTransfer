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
		#region Initiator Overloads
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
		public static Tunnel CreateInitiator<T>(
			Stream stream
			, RSACryptoServiceProvider localPrivateKey
			, IEnumerable<T> remoteIds
			, out T remoteIdentity
			, out TunnelCreationError error
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, bool leaveOpen = false
#endif
		) where T : IHasPublicKeySha => CreateInitiator(
			stream
			, localPrivateKey
			, remoteIds
			, x => x.GetPublicKeySha()
			, out remoteIdentity
			, out error
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
		public static Tunnel CreateInitiator(
			Stream stream
			, RSACryptoServiceProvider localPrivateKey
			, IEnumerable<byte[]> remotePublicKeyHashes
			, out byte[] remotePublicKeyHash
			, out TunnelCreationError error
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, bool leaveOpen = false
#endif
		) => CreateInitiator(
			stream
			, localPrivateKey
			, remotePublicKeyHashes
			, x => x
			, out remotePublicKeyHash
			, out error
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, leaveOpen
#endif
		);
		#endregion


		#region Initiator Overloads
		/// <summary>
		/// Responds to a handshake to setup secure connection over <see cref="Stream"/>.
		/// </summary>
		/// <typeparam name="T">Identity type.</typeparam>
		/// <param name="stream">The underlying stream. Usually expected to be a network stream.</param>
		/// <param name="localPrivateKey">The private key you use to connect.</param>
		/// <param name="remoteIds">Identifies the public keys that are allowed, encoded as Csp blobs. Can be left <see langword="null"/> to allow connection to anyone. Key can also be found later using <see cref="RemotePublicKey"/> property.</param>
		/// <param name="remoteIdentity">The element of <paramref name="remoteIds"/> that matched the remote's public key. If there was an error or <paramref name="remoteIds"/> was <see langword="null"/> this may be left default.</param>
		/// <param name="error">An error message for if something goes wrong.</param>
		/// <param name="leaveOpen">True to not close the underlying stream when the <see cref="Tunnel"/> is closed.</param>
		/// <returns>The new stream that wraps <paramref name="stream"/> with end to end encyption.</returns>
		public static Tunnel CreateResponder<T>(
			Stream stream
			, RSACryptoServiceProvider localPrivateKey
			, IEnumerable<T> remoteIds
			, out T remoteIdentity
			, out TunnelCreationError error
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, bool leaveOpen = false
#endif
		) where T : IHasPublicKeySha => CreateResponder(
			stream
			, localPrivateKey
			, remoteIds
			, x => x.GetPublicKeySha()
			, out remoteIdentity
			, out error
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, leaveOpen
#endif
		);

		/// <summary>
		/// Responds to a handshake to setup secure connection over <see cref="Stream"/>.
		/// </summary>
		/// <param name="stream">The underlying stream. Usually expected to be a network stream.</param>
		/// <param name="localPrivateKey">The private key you use to connect.</param>
		/// <param name="remotePublicKeyHashes">The SHA256 hashes of the public keys (encoded as Csp blobs) that are allowed. Can be left <see langword="null"/> to allow connection to anyone. Key can also be found later using <see cref="RemotePublicKey"/> property (this is the original, not the hash).</param>
		/// <param name="remotePublicKeyHash">The element of <paramref name="remotePublicKeyHashes"/> that matched the remote's public key. If there was an error or <paramref name="remotePublicKeyHashes"/> was <see langword="null"/> this may be left default.</param>
		/// <param name="error">An error message for if something goes wrong.</param>
		/// <param name="leaveOpen">True to not close the underlying stream when the <see cref="Tunnel"/> is closed.</param>
		/// <returns>The new stream that wraps <paramref name="stream"/> with end to end encyption.</returns>
		public static Tunnel CreateResponder(
			Stream stream
			, RSACryptoServiceProvider localPrivateKey
			, IEnumerable<byte[]> remotePublicKeyHashes
			, out byte[] remotePublicKeyHash
			, out TunnelCreationError error
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, bool leaveOpen = false
#endif
		) => CreateResponder(
			stream
			, localPrivateKey
			, remotePublicKeyHashes
			, x => x
			, out remotePublicKeyHash
			, out error
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, leaveOpen
#endif
		);
		#endregion
		#endregion

		// All sizes below are listed in bytes.
		/// <summary>
		/// Size of the challenge message in bytes to initiate connection.
		/// </summary>
		private const uint CHALLANGE_SIZE = 16;
		private const bool USE_OAEP_PADDING = true;
		private const uint AES_KEY_LENGTH = 32; // 256 bit key
		private const uint AES_IV_LENGTH = 16;  // Part of AES definition
		private const uint AES_BLOCK_SIZE = 16; // Part of AES definition
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
		/// <summary>
		/// The CspBlob for the remote key for the other end of the connection. Can be used as an identity.
		/// </summary>
		public byte[] RemotePublicKey { private set; get; }

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
		private static Aes ReadAesKey(BinaryReader bw, RSACryptoServiceProvider rsa)
		{
			var aes = aeskey();
			using (var memStream = new MemoryStream(rsa.Decrypt(bw.ReadBinaryData(), USE_OAEP_PADDING)))
			using (var writer = new BinaryReader(memStream))
			{
				byte[] bytes;
				bytes = new byte[AES_KEY_LENGTH];
				memStream.Read(bytes, 0, (int)AES_KEY_LENGTH);
				aes.Key = bytes;

				bytes = new byte[AES_IV_LENGTH];
				memStream.Read(bytes, 0, (int)AES_IV_LENGTH);
				aes.IV = bytes;
			}
			return aes;
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
		/// Initiates handshake to setup secure connection over <see cref="Stream"/>.
		/// </summary>
		/// <param name="stream">The underlying stream. Usually expected to be a network stream.</param>
		/// <param name="localPrivateKey">The private key you use to connect.</param>
		/// <param name="remoteIds">A collection of remote Ids that are acceptable. Can be left <see langword="null"/> to ingore verification.</param>
		/// <param name="publicKeyShaExtractor">A function that gets the SHA256 hash of a public key encoded as a CspBlob from elements of <paramref name="remoteIds"/>.</param>
		/// <param name="remoteIdentity">The element of <paramref name="remoteIds"/> that matched the remote's public key. If there was an error or <paramref name="remoteIds"/> was <see langword="null"/> this may be left default.</param>
		/// <param name="error">An error message for if something goes wrong.</param>
		/// <param name="leaveOpen">True to not close the underlying stream when the <see cref="Tunnel"/> is closed.</param>
		/// <returns>The new stream that wraps <paramref name="stream"/> with end to end encyption.</returns>
		public static Tunnel CreateInitiator<Id>(
			Stream stream
			, RSACryptoServiceProvider localPrivateKey
			, IEnumerable<Id> remoteIds
			, Func<Id, byte[]> publicKeyShaExtractor
			, out Id remoteIdentity
			, out TunnelCreationError error
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
					using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
					using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
					{
						// write some metadata
						var remoteVersion = ReadAndWriteVersion(writer, reader);
						if (remoteVersion != VERSION_NUMBER)
						{
							error = remoteVersion < VERSION_NUMBER ? TunnelCreationError.RemoteNeedsUpgrade : TunnelCreationError.INeedUpgrade;
							remoteIdentity = default;
							return null;
						}

						// write public key
						writer.WriteBinaryData(localPrivateKey.ExportCspBlob(false));

						// read encrypted AES key
						using (var sharedKey = ReadAesKey(reader, localPrivateKey))
						{
							output.InitCryptoStreams(sharedKey);
						}
					}

					// From here on in everything is encrypted with AES key
					using (var writer = new BinaryWriter(output, Encoding.UTF8, true))
					using (var reader = new BinaryReader(output, Encoding.UTF8, true))
					{
						// write challenge
						var challengeMessage = new byte[CHALLANGE_SIZE];
						using (var rand = new RNGCryptoServiceProvider())
							rand.GetBytes(challengeMessage);
						writer.Write(challengeMessage);

						// write block of zeros.
						writer.Write(new byte[AES_BLOCK_SIZE]);

						// read remote public key
						output.RemotePublicKey = reader.ReadBinaryData();
						Debug.WriteLine($"{output.RemotePublicKey.Length} {Convert.ToBase64String(output.RemotePublicKey)}");
						if (remoteIds != null)
						{
							var remotePublicKeySha = hash.ComputeHash(output.RemotePublicKey);

							if (remoteIds.TryFirst(x => publicKeyShaExtractor(x).SequenceEquals(remotePublicKeySha), out var id))
							{
								remoteIdentity = id;
							}
							else
							{
								output.Dispose();
								error = TunnelCreationError.RemoteDoesNotHaveValidPublicKey;
								remoteIdentity = default;
								return null;
							}
						}
						else
							remoteIdentity = default;

						using (var remotePublicKey = new RSACryptoServiceProvider())
						{
							remotePublicKey.ImportCspBlob(output.RemotePublicKey);

							// read challenge signature
							if (!remotePublicKey.VerifyData(challengeMessage, hash, reader.ReadBinaryData()))
							{
								output.Dispose();
								error = TunnelCreationError.RemoteFailedToVierfyItself;
								return null;
							}

							error = TunnelCreationError.NoError;
							return output;
						}
					}
				}
			}
			catch
			{
				output.Dispose();
				throw;
			}
		}

		/// <summary>
		/// Responds to a handshake to setup secure connection over <see cref="Stream"/>.
		/// </summary>
		/// <param name="stream">The underlying stream. Usually expected to be a network stream.</param>
		/// <param name="localPrivateKey">The private key you use to connect.</param>
		/// <param name="remoteIds">A collection of remote Ids that are acceptable. Can be left <see langword="null"/> to ingore verification.</param>
		/// <param name="publicKeyShaExtractor">A function that gets the SHA256 hash of a public key encoded as a CspBlob from elements of <paramref name="remoteIds"/>.</param>
		/// <param name="remoteIdentity">The element of <paramref name="remoteIds"/> that matched the remote's public key. If there was an error or <paramref name="remoteIds"/> was <see langword="null"/> this may be left default.</param>
		/// <param name="error">An error message for if something goes wrong.</param>
		/// <param name="leaveOpen">True to not close the underlying stream when the <see cref="Tunnel"/> is closed.</param>
		public static Tunnel CreateResponder<Id>(
			Stream stream
			, RSACryptoServiceProvider localPrivateKey
			, IEnumerable<Id> remoteIds
			, Func<Id, byte[]> publicKeyShaExtractor
			, out Id remoteIdentity
			, out TunnelCreationError error
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
					using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
					using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
					{
						// read some metadata
						var remoteVersion = ReadAndWriteVersion(writer, reader);
						if (remoteVersion != VERSION_NUMBER)
						{
							output.Dispose();
							error = remoteVersion < VERSION_NUMBER ? TunnelCreationError.RemoteNeedsUpgrade : TunnelCreationError.INeedUpgrade;
							remoteIdentity = default;
							return null;
						}

						//TODO put in protection from dos attack where they just give a massive byte array.
						// read remote public key
						output.RemotePublicKey = reader.ReadBinaryData();
						if (remoteIds != null)
						{
							var remotePublicKeySha = hash.ComputeHash(output.RemotePublicKey);

							if (remoteIds.TryFirst(x => publicKeyShaExtractor(x).SequenceEquals(remotePublicKeySha), out var id))
							{
								remoteIdentity = id;
							}
							else
							{
								output.Dispose();
								error = TunnelCreationError.RemoteDoesNotHaveValidPublicKey;
								remoteIdentity = default;
								return null;
							}

						}
						else
							remoteIdentity = default;

						using (var remotePublicKey = new RSACryptoServiceProvider())
						{
							remotePublicKey.ImportCspBlob(output.RemotePublicKey);

							// write encrypted AES key
							using (var sharedKey = aeskey())
							{
								sharedKey.GenerateKey();
								sharedKey.GenerateIV();
								WriteAesKey(sharedKey, writer, remotePublicKey);

								output.InitCryptoStreams(sharedKey);
							}
						}
					}

					// frome here on in everything is encrytped with AES key.
					using (var reader = new BinaryReader(output, Encoding.UTF8, true))
					using (var writer = new BinaryWriter(output, Encoding.UTF8, true))
					{
						// write local public key
						var pubkey = localPrivateKey.ExportCspBlob(false);
						Debug.WriteLine($"{pubkey.Length} {Convert.ToBase64String(pubkey)}");
						writer.WriteBinaryData(pubkey);

						// read challenge
						var challengeMessage = reader.ReadBytes((int)CHALLANGE_SIZE);

						// write challenge signature
						var sig = localPrivateKey.SignData(challengeMessage, hash);
						writer.WriteBinaryData(sig);

						// read block of zeros
						var zeros = reader.ReadBytes((int)AES_BLOCK_SIZE);

						if (!new byte[AES_BLOCK_SIZE].SequenceEquals(zeros))
						{
							output.Dispose();
							error = TunnelCreationError.RemoteFailedToVierfyItself;
							return null;
						}
					}

					error = TunnelCreationError.NoError;
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
