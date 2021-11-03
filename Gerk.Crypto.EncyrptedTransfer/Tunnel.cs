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
	public enum TunnelCreationError
	{
		NoError = 0,
		RemoteDoesNotHaveValidPublicKey,
		RemoteFailedToVierfyItself,
	}


	public class Tunnel : Stream
	{
		/// <summary>
		/// Size of the challenge message in bytes to initiate connection.
		/// </summary>
		private const int CHALLANGE_SIZE = 256;
		private const bool USE_OAEP_PADDING = true;
		private const int AES_KEY_LENGTH = 256;

		private CryptoStream readStream;
		private CryptoStream writeStream;
		private Aes sharedKey = null;
		private Stream underlyingStream;
		private ulong bytesRead = 0;
		private uint readBlockSize;
		private ulong bytesWritten = 0;
		private uint writeBlockSize;
		public uint BlockSize => writeBlockSize;

		private bool leaveOpen;

		/// <summary>
		/// The public key for the other end of the connection. Can be used as an identity.
		/// </summary>
		public RSAParameters remotePublicKey { private set; get; }

		private Tunnel(Stream stream, bool leaveOpen)
		{
			this.underlyingStream = stream;
			this.leaveOpen = leaveOpen;
		}
		private void InitCryptoStreams()
		{
			var dec = sharedKey.CreateDecryptor();
			var enc = sharedKey.CreateEncryptor();
			readBlockSize = (uint)dec.OutputBlockSize;
			writeBlockSize = (uint)enc.InputBlockSize;
			readStream = new CryptoStream(underlyingStream, dec, CryptoStreamMode.Read);
			writeStream = new CryptoStream(underlyingStream, enc, CryptoStreamMode.Write);
		}

		private static Aes ReadAesKey(BinaryReader bw, RSACryptoServiceProvider rsa)
		{
			var aes = Aes.Create();
			using (var memStream = new MemoryStream(rsa.Decrypt(bw.ReadBinaryData(), USE_OAEP_PADDING)))
			using (var memReader = new BinaryReader(memStream))
			{
				aes.Key = memReader.ReadBinaryData();
				aes.IV = memReader.ReadBinaryData();
			}
			return aes;
		}

		private static void WriteAesKey(Aes aes, BinaryWriter bw, RSACryptoServiceProvider rsa)
		{
			using (var memStream = new MemoryStream())
			using (var memWriter = new BinaryWriter(memStream))
			{
				memWriter.WriteBinaryData(aes.Key);
				memWriter.WriteBinaryData(aes.IV);
				bw.WriteBinaryData(rsa.Encrypt(memStream.ToArray(), USE_OAEP_PADDING));
			}
		}

		public static Tunnel CreateInitiator(Stream stream, IEnumerable<RSAParameters> remotePublicKeys, RSACryptoServiceProvider localPrivateKey, out TunnelCreationError error, bool leaveOpen = false)
		{
			Tunnel output = new Tunnel(stream, leaveOpen);
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

		public static Tunnel CreateResponder(Stream stream, IEnumerable<RSAParameters> remotePublicKeys, RSACryptoServiceProvider localPrivateKey, out TunnelCreationError error, bool leaveOpen = false)
		{
			Tunnel output = new Tunnel(stream, leaveOpen);
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
						output.sharedKey = Aes.Create();
						output.sharedKey.KeySize = AES_KEY_LENGTH;
						output.sharedKey.GenerateIV();
						WriteAesKey(output.sharedKey, writer, remotePublicKey);
					}

					// read challenge
					byte[] challengeMessage = new byte[CHALLANGE_SIZE];
					reader.Read(challengeMessage, 0, CHALLANGE_SIZE);

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
			int bytesToWrite = (int)(writeBlockSize - bytesWritten % writeBlockSize);
			if (bytesToWrite != writeBlockSize)
				Write(new byte[bytesToWrite], 0, bytesToWrite);
		}

		public virtual void FlushReader()
		{
			int bytesToRead = (int)(readBlockSize - bytesRead % readBlockSize);
			if (bytesToRead != readBlockSize)
				Write(new byte[bytesToRead], 0, bytesToRead);
		}

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
			if (!leaveOpen)
				await underlyingStream.DisposeAsync();
			await a;
			await b;
		}
#endif

		public override void Close()
		{
			sharedKey.Dispose();
			writeStream?.Close();
			readStream?.Close();
			if (!leaveOpen)
				underlyingStream?.Close();
		}
	}
}
