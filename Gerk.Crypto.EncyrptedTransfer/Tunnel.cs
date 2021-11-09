using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Gerk.BinaryExtension;

namespace Gerk.Crypto.EncyrptedTransfer
{
	/// <summary>
	/// A <see cref="Stream"/> for end to end encrypted and secure transfering of data. Data is only written to the underlying stream in blocks. You can complete a block that needs to be written by using <see cref="FlushWriter"/>. When reading, wherever you expect a block to be completed by a <see cref="FlushWriter"/> you should call <see cref="FlushReader"/> to jump to the end of the block. Wrapping this stream with a <see cref="StreamReader"/> or <see cref="StreamWriter"/> is not currently supported. Rather you are encouraged to use a <see cref="BinaryReader"/> and <see cref="BinaryWriter"/>.
	/// </summary>
	public class Tunnel : Stream
	{
		// All sizes below are listed in bytes.
		/// <summary>
		/// Size of the challenge message in bytes to initiate connection.
		/// </summary>
		private const uint CHALLANGE_SIZE = 16;
		private const bool USE_OAEP_PADDING = true;
		private const uint AES_KEY_LENGTH = 32; // 256 bit key
		private const uint AES_IV_LENGTH = 16; // Part of AES definition
		private const uint AES_BLOCK_SIZE = 16; // Part of AES definition

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
		/// The public key for the other end of the connection. Can be used as an identity.
		/// </summary>
		public RSAParameters RemotePublicKey { private set; get; }

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="stream">The underlying stream.</param>
		/// <param name="leaveOpen">Whether to leave open or not.</param>
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
		private Tunnel(Stream stream, bool leaveOpen = false)
		{
			this.leaveOpen = leaveOpen;
#else
		private Tunnel(Stream stream)
		{
#endif
			this.underlyingStream = stream;
		}

		/// <summary>
		/// Creates <see cref="CryptoStream"/>s.
		/// </summary>
		/// <param name="sharedKey">The initialized AES key.</param>
		private void InitCryptoStreams(Aes sharedKey)
		{
			var dec = sharedKey.CreateDecryptor();
			var enc = sharedKey.CreateEncryptor();
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			readStream = new CryptoStream(underlyingStream, dec, CryptoStreamMode.Read, leaveOpen);
			writeStream = new CryptoStream(underlyingStream, enc, CryptoStreamMode.Write, leaveOpen);
#else
			readStream = new CryptoStream(underlyingStream, dec, CryptoStreamMode.Read);
			writeStream = new CryptoStream(underlyingStream, enc, CryptoStreamMode.Write);
#endif
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

		/// <summary>
		/// Initiates handshake to setup secure connection over <see cref="Stream"/>.
		/// </summary>
		/// <param name="stream">The underlying stream. Usually expected to be a network stream.</param>
		/// <param name="remotePublicKeys">The public keys that are allowed. Can be left <see langword="null"/> to allow connection to anyone. Key can also be found later using <see cref="RemotePublicKey"/> property.</param>
		/// <param name="localPrivateKey">The private key you use to connect.</param>
		/// <param name="error">An error message for if something goes wrong.</param>
		/// <param name="leaveOpen">True to not close the underlying stream when the <see cref="Tunnel"/> is closed.</param>
		/// <returns>The new stream that wraps <paramref name="stream"/> with end to end encyption.</returns>
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
		public static Tunnel CreateInitiator(Stream stream, IEnumerable<RSAParameters> remotePublicKeys, RSACryptoServiceProvider localPrivateKey, out TunnelCreationError error, bool leaveOpen = false)
#else
		public static Tunnel CreateInitiator(Stream stream, IEnumerable<RSAParameters> remotePublicKeys, RSACryptoServiceProvider localPrivateKey, out TunnelCreationError error)
#endif
		{
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			var output = new Tunnel(stream, leaveOpen);
#else
			var output = new Tunnel(stream);
#endif
			try
			{
				using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
				using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
				{
					// write some metadata

					// write public key
					writer.WriteBinaryData(localPrivateKey.ExportCspBlob(false));

					// write challenge
					var challengeMessage = new byte[CHALLANGE_SIZE];
					using (var rand = new RNGCryptoServiceProvider())
						rand.GetBytes(challengeMessage);
					writer.Write(challengeMessage);

					// read encrypted AES key
					using (var sharedKey = ReadAesKey(reader, localPrivateKey))
					using (var remotePublicKey = new RSACryptoServiceProvider())
					{
						// read remote public key
						remotePublicKey.ImportCspBlob(reader.ReadBinaryData());
						output.RemotePublicKey = remotePublicKey.ExportParameters(false);
						if (remotePublicKeys != null && !remotePublicKeys.Any(x => x.Modulus.SequenceEqual(output.RemotePublicKey.Modulus)))
						{
							output.Dispose();
							error = TunnelCreationError.RemoteDoesNotHaveValidPublicKey;
							return null;
						}

						// read challenge signature
						using (var hash = SHA256.Create())
							if (!remotePublicKey.VerifyData(challengeMessage, hash, reader.ReadBinaryData()))
							{
								output.Dispose();
								error = TunnelCreationError.RemoteFailedToVierfyItself;
								return null;
							}

						output.InitCryptoStreams(sharedKey);
					}
				}
				error = TunnelCreationError.NoError;
				return output;
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
		/// <param name="remotePublicKeys">The public keys that are allowed. Can be left <see langword="null"/> to allow connection from anyone. Key can also be found later using <see cref="RemotePublicKey"/> property.</param>
		/// <param name="localPrivateKey">The private key you use to connect.</param>
		/// <param name="error">An error message for if something goes wrong.</param>
		/// <param name="leaveOpen">True to not close the underlying stream when the <see cref="Tunnel"/> is closed.</param>
		/// <returns>The new stream that wraps <paramref name="stream"/> with end to end encyption.</returns>
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
		public static Tunnel CreateResponder(Stream stream, IEnumerable<RSAParameters> remotePublicKeys, RSACryptoServiceProvider localPrivateKey, out TunnelCreationError error, bool leaveOpen = false)
#else
		public static Tunnel CreateResponder(Stream stream, IEnumerable<RSAParameters> remotePublicKeys, RSACryptoServiceProvider localPrivateKey, out TunnelCreationError error)
#endif
		{
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			var output = new Tunnel(stream, leaveOpen);
#else
			var output = new Tunnel(stream);
#endif
			try
			{
				using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
				using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
				{
					// read some metadata

					// read public key
					using (var remotePublicKey = new RSACryptoServiceProvider())
					{
						remotePublicKey.ImportCspBlob(reader.ReadBinaryData());
						output.RemotePublicKey = remotePublicKey.ExportParameters(false);
						if (remotePublicKeys != null && !remotePublicKeys.Any(x => x.Modulus.SequenceEqual(output.RemotePublicKey.Modulus)))
						{
							output.Dispose();
							error = TunnelCreationError.RemoteDoesNotHaveValidPublicKey;
							return null;
						}

						// write encrypted AES key
						using (var sharedKey = aeskey())
						{
							sharedKey.GenerateKey();
							sharedKey.GenerateIV();
							WriteAesKey(sharedKey, writer, remotePublicKey);

							// read challenge
							byte[] challengeMessage = new byte[CHALLANGE_SIZE];
							reader.Read(challengeMessage, 0, (int)CHALLANGE_SIZE);

							// write local public key
							writer.WriteBinaryData(localPrivateKey.ExportCspBlob(false));

							// write challenge signature
							using (var hash = SHA256.Create())
								writer.WriteBinaryData(localPrivateKey.SignData(challengeMessage, hash));

							output.InitCryptoStreams(sharedKey);
						}
					}
				}

				error = TunnelCreationError.NoError;
				return output;
			}
			catch
			{
				output.Dispose();
				throw;
			}
		}

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

		/// <summary>
		/// Writes 0s to the stream until the end the current block so it can be sent.
		/// </summary>
		public virtual void FlushWriter()
		{
			int bytesToWrite = (int)(BlockSize - (bytesWritten % BlockSize));
			if (bytesToWrite != BlockSize)
				Write(new byte[bytesToWrite], 0, bytesToWrite);
		}

		/// <summary>
		/// Skips to the end of the current block. Meant to skip the 0s wrote by <see cref="FlushWriter"/>.
		/// </summary>
		public virtual void FlushReader()
		{
			int bytesToRead = (int)(BlockSize - bytesRead % BlockSize);
			if (bytesToRead != BlockSize)
				Write(new byte[bytesToRead], 0, bytesToRead);
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
			writeStream?.Close();
			readStream?.Close();
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			if (!leaveOpen)
#endif
				underlyingStream?.Close();
		}
	}
}
