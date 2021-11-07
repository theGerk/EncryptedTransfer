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
	/// Error code for errors that happen during the tunnel creation
	/// </summary>
	/// <seealso cref="Tunnel.CreateInitiator(Stream, IEnumerable{RSAParameters}, RSACryptoServiceProvider, out TunnelCreationError, bool)"/>
	/// <seealso cref="Tunnel.CreateResponder(Stream, IEnumerable{RSAParameters}, RSACryptoServiceProvider, out TunnelCreationError, bool)"/>
	public enum TunnelCreationError
	{
		/// <summary>
		/// All good, no errors.
		/// </summary>
		NoError = 0,
		/// <summary>
		/// The other side of the tunnel provided an invalid public key.
		/// </summary>
		RemoteDoesNotHaveValidPublicKey,
		/// <summary>
		/// The other side of the tunnel failed to prove their identiity.
		/// </summary>
		RemoteFailedToVierfyItself,
	}

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

		private CryptoStream readStream;
		private CryptoStream writeStream;
		private Aes sharedKey;
		private readonly Stream underlyingStream;
		private ulong bytesRead = 0;
		private ulong bytesWritten = 0;
		/// <summary>
		/// The size in bytes of each block. 
		/// </summary>
		public static uint BlockSize => AES_BLOCK_SIZE;

#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
		private bool leaveOpen;
#endif
		/// <summary>
		/// The public key for the other end of the connection. Can be used as an identity.
		/// </summary>
		public RSAParameters remotePublicKey { private set; get; }

		/// <summary>
		/// 
		/// </summary>
		/// <param name="stream"></param>
		/// <param name="leaveOpen"></param>
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
		private Tunnel(Stream stream, bool leaveOpen = false)
		{
			this.underlyingStream = stream;
			this.leaveOpen = leaveOpen;
		}
#else
		private Tunnel(Stream stream)
		{
			this.underlyingStream = stream;
		}
#endif

		private void InitCryptoStreams()
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

		private static void WriteAesKey(Aes aes, BinaryWriter bw, RSACryptoServiceProvider rsa)
		{
			using (var memStream = new MemoryStream())
			{
				memStream.Write(aes.Key, 0, (int)AES_KEY_LENGTH);
				memStream.Write(aes.IV, 0, (int)AES_IV_LENGTH);
				bw.WriteBinaryData(rsa.Encrypt(memStream.ToArray(), USE_OAEP_PADDING));
			}
		}

		private static Aes aeskey()
		{
			var output = Aes.Create();
			output.Mode = CipherMode.CBC;
			output.Padding = PaddingMode.None;
			return output;
		}

		public static Tunnel CreateInitiator(Stream stream, IEnumerable<RSAParameters> remotePublicKeys, RSACryptoServiceProvider localPrivateKey, out TunnelCreationError error
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, bool leaveOpen = false
#endif
		)
		{
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			Tunnel output = new Tunnel(stream, leaveOpen);
#else
			Tunnel output = new Tunnel(stream);
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
					output.sharedKey = ReadAesKey(reader, localPrivateKey);

					// read remote public key
					using (var remotePublicKey = new RSACryptoServiceProvider())
					{
						remotePublicKey.ImportCspBlob(reader.ReadBinaryData());
						output.remotePublicKey = remotePublicKey.ExportParameters(false);
						if (!remotePublicKeys.Any(x => x.Modulus.SequenceEqual(output.remotePublicKey.Modulus)))
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
					}
				}

				output.InitCryptoStreams();
				error = TunnelCreationError.NoError;
				return output;
			}
			catch
			{
				output.Dispose();
				throw;
			}
		}

		public static Tunnel CreateResponder(Stream stream, IEnumerable<RSAParameters> remotePublicKeys, RSACryptoServiceProvider localPrivateKey, out TunnelCreationError error
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			, bool leaveOpen = false
#endif
			)
		{
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			Tunnel output = new Tunnel(stream, leaveOpen);
#else
			Tunnel output = new Tunnel(stream);
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
						output.remotePublicKey = remotePublicKey.ExportParameters(false);
						if (!remotePublicKeys.Any(x => x.Modulus.SequenceEqual(output.remotePublicKey.Modulus)))
						{
							output.Dispose();
							error = TunnelCreationError.RemoteDoesNotHaveValidPublicKey;
							return null;
						}

						// write encrypted AES key
						output.sharedKey = aeskey();
						output.sharedKey.GenerateKey();
						output.sharedKey.GenerateIV();
						WriteAesKey(output.sharedKey, writer, remotePublicKey);
					}

					// read challenge
					byte[] challengeMessage = new byte[CHALLANGE_SIZE];
					reader.Read(challengeMessage, 0, (int)CHALLANGE_SIZE);

					// write local public key
					writer.WriteBinaryData(localPrivateKey.ExportCspBlob(false));

					// write challenge signature
					using (var hash = SHA256.Create())
						writer.WriteBinaryData(localPrivateKey.SignData(challengeMessage, hash));
				}

				output.InitCryptoStreams();
				error = TunnelCreationError.NoError;
				return output;
			}
			catch
			{
				output.Dispose();
				throw;
			}
		}

		public override bool CanRead => true;

		public override bool CanSeek => false;

		public override bool CanWrite => true;

		public override long Length => throw new NotSupportedException();

		public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

		public override void Flush() => underlyingStream.Flush();

		public virtual void FlushWriter()
		{
			int bytesToWrite = (int)(BlockSize - (bytesWritten % BlockSize));
			if (bytesToWrite != BlockSize)
				Write(new byte[bytesToWrite], 0, bytesToWrite);
		}

		public virtual void FlushReader()
		{
			int bytesToRead = (int)(BlockSize - bytesRead % BlockSize);
			if (bytesToRead != BlockSize)
				Write(new byte[bytesToRead], 0, bytesToRead);
		}
#if NET5_0
		public string GetKey()
		{
			byte[] me = new byte[16];
			var hash = SHA256.HashData(sharedKey.Key);
			Buffer.BlockCopy(hash, 0, me, 0, 16);
			return new Guid(me).ToString();
		}
#endif
		public override int Read(byte[] buffer, int offset, int count)
		{
			var read = readStream.Read(buffer, offset, count);
			bytesRead += (ulong)read;
			return read;
		}

		public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

		public override void SetLength(long value) => throw new NotSupportedException();

		public override void Write(byte[] buffer, int offset, int count)
		{
			bytesWritten += (ulong)count;
			writeStream.Write(buffer, offset, count);
		}

#if NETCOREAPP3_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		public override async ValueTask DisposeAsync()
		{
			sharedKey.Dispose();
			var a = writeStream.DisposeAsync();
			var b = readStream.DisposeAsync();
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			if (!leaveOpen)
				await underlyingStream.DisposeAsync();
#endif
			await a;
			await b;
		}
#endif

		public override void Close()
		{
			sharedKey.Dispose();
			writeStream?.Close();
			readStream?.Close();
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
			if (!leaveOpen)
#endif
				underlyingStream?.Close();
		}
	}
}
