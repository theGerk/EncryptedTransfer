using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Gerk.BinaryExtension;

namespace Gerk.Crypto.EncyrptedTransfer
{
	public class Tunnel : Stream
	{
		/// <summary>
		/// Size of the challenge message in bytes to initiate connection.
		/// </summary>
		private const int CHALLANGE_SIZE = 256;
		private const bool USE_OAEP_PADDING = true;

		private Aes sharedKey = null;
		private Stream stream;
		/// <summary>
		/// The public key for the other end of the connection. Can be used as an identity.
		/// </summary>
		public RSAParameters remotePublicKey { private set; get; }

		private Tunnel(Stream stream)
		{
			this.stream = stream;
		}

		public static Tunnel CreateInitiator(Stream stream, IEnumerable<RSAParameters> remotePublicKeys, RSACryptoServiceProvider localPrivateKey)
		{
			Tunnel output = new Tunnel(stream);
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
					output.sharedKey = Aes.Create();
					output.sharedKey.Key = localPrivateKey.Decrypt(reader.ReadBinaryData(), USE_OAEP_PADDING);

					// read remote public key
					using (var remotePublicKey = new RSACryptoServiceProvider())
					{
						remotePublicKey.ImportCspBlob(reader.ReadBinaryData());
						output.remotePublicKey = remotePublicKey.ExportParameters(false);
						if (!remotePublicKeys.Any(x => x.Modulus == output.remotePublicKey.Modulus))
						{
							output.Dispose();
							return null;
						}

						// read challenge signature
						output.sharedKey = Aes.Create();
						using (var hash = SHA256.Create())
							if (!remotePublicKey.VerifyData(challengeMessage, hash, reader.ReadBinaryData()))
								throw new CryptographicException("Remote target was not able to verify themselves correctly.");
					}
				}
				return output;
			}
			catch
			{
				output.Dispose();
				throw;
			}
		}

		public static Tunnel CreateResponder(Stream stream, IEnumerable<RSAParameters> remotePublicKeys, RSACryptoServiceProvider localPrivateKey)
		{
			Tunnel output = new Tunnel(stream);
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
						if (!remotePublicKeys.Any(x => x.Modulus == output.remotePublicKey.Modulus))
						{
							output.Dispose();
							return null;
						}

						// write encrypted AES key
						output.sharedKey = Aes.Create();
						writer.WriteBinaryData(remotePublicKey.Encrypt(output.sharedKey.Key, USE_OAEP_PADDING));
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
				return output;
			}
			catch
			{
				output.Dispose();
				throw;
			}
		}

		public override bool CanRead => throw new System.NotImplementedException();

		public override bool CanSeek => throw new System.NotImplementedException();

		public override bool CanWrite => throw new System.NotImplementedException();

		public override long Length => throw new System.NotImplementedException();

		public override long Position { get => throw new System.NotImplementedException(); set => throw new System.NotImplementedException(); }

		public override void Flush()
		{
			throw new System.NotImplementedException();
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			throw new System.NotImplementedException();
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new System.NotImplementedException();
		}

		public override void SetLength(long value)
		{
			throw new System.NotImplementedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new System.NotImplementedException();
		}
	}
}
