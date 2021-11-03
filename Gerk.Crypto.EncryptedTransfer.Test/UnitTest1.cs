using Gerk.Crypto.EncyrptedTransfer;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Gerk.Crypto.EncryptedTransfer.Test
{
	public class UnitTest1
	{
		public byte[] reciver(Stream stream, RSAParameters local, RSAParameters remote)
		{
			using var rsa = new RSACryptoServiceProvider();
			rsa.ImportParameters(local);
			using var tunnel = Tunnel.CreateResponder(stream, new RSAParameters[] { remote }, rsa, out var err);
			if (err != TunnelCreationError.NoError)
				throw new Exception(err.ToString());
			var buf = new byte[tunnel.BlockSize];
			tunnel.Read(buf, 0, buf.Length);
			return buf;
		}

		public void send(Stream stream, RSAParameters local, RSAParameters remote, byte[] msg)
		{
			using var rsa = new RSACryptoServiceProvider();
			rsa.ImportParameters(local);
			using var tunnel = Tunnel.CreateInitiator(stream, new RSAParameters[] { remote }, rsa, out var err);
			if (err != TunnelCreationError.NoError)
				throw new Exception(err.ToString());
			tunnel.Write(new byte[tunnel.BlockSize], 0, (int)tunnel.BlockSize);
		}

		[Fact]
		public void Test1()
		{

		}
	}

	public class FakeNetworkStream : Stream
	{
		private class ByteStream
		{
			Queue<ReadOnlyMemory<byte>> q = new();
			ReadOnlyMemory<byte> current = new();
			int i = 0;
			TaskCompletionSource readTask = null;
			readonly object lockobj = new();
			public void write(ReadOnlyMemory<byte> bytes)
			{
				if (!bytes.IsEmpty)
				{
					lock (lockobj)
					{
						q.Enqueue(bytes);
						if (readTask != null)
							readTask.TrySetResult();
					}
				}
			}

			public async ValueTask<int> read(Memory<byte> buffer)
			{
				if (i >= current.Length)
				{
					lock (lockobj)
					{
						bool queueHadAnything = q.TryDequeue(out current);
						if (queueHadAnything)
						{
							i = 0;
						}
						else
						{
							// need to use taskcompletionsource here
						}
					}
				}

				
			}
		}


		public override bool CanRead => true;

		public override bool CanSeek => false;

		public override bool CanWrite => true;

		public override long Length => throw new NotSupportedException();

		public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

		public override void Flush() { }

		public override int Read(byte[] buffer, int offset, int count)
		{
			using var sync = new SynchronizationContextSwap.SynchronizationContextSwap<bool>();
			return ReadAsync(buffer, offset, count, CancellationToken.None).Result;
		}

		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
		{
			return base.ReadAsync(buffer, offset, count, cancellationToken);
		}

		public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			return base.ReadAsync(buffer, cancellationToken);
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotImplementedException();
		}

		public override void SetLength(long value)
		{
			throw new NotImplementedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotImplementedException();
		}
	}
}
