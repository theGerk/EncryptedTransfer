using Gerk.AsyncThen;
using Gerk.Crypto.EncyrptedTransfer;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;
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

		public void sender(Stream stream, RSAParameters local, RSAParameters remote)
		{
			using var rsa = new RSACryptoServiceProvider();
			rsa.ImportParameters(local);
			using var tunnel = Tunnel.CreateInitiator(stream, new RSAParameters[] { remote }, rsa, out var err);
			if (err != TunnelCreationError.NoError)
				throw new Exception(err.ToString());
			tunnel.Write(new byte[tunnel.BlockSize], 0, (int)tunnel.BlockSize);
		}

		[Fact]
		public async Task Test1()
		{
			var (a, b) = FakeNetworkStream.Create();
			using var c = new RSACryptoServiceProvider();
			using var d = new RSACryptoServiceProvider();
			var sendTask = Task.Run(() => sender(a, c.ExportParameters(true), d.ExportParameters(false)));
			var reciveTask = Task.Run(() => reciver(b, d.ExportParameters(true), c.ExportParameters(false)));
			await Task.WhenAll(sendTask, reciveTask);
			Assert.True((await reciveTask).SequenceEqual(new byte[16]));
		}
	}

	public class FakeNetworkStream : Stream
	{
		private class ByteStream
		{
			Queue<ReadOnlyMemory<byte>> q = new();
			ReadOnlyMemory<byte> current = new();
			int i = 0;
			TaskCompletionSource readTaskSource = null;
			readonly object lockobj = new();
			public void Write(ReadOnlyMemory<byte> bytes)
			{
				if (!bytes.IsEmpty)
				{
					lock (lockobj)
					{
						q.Enqueue(bytes);
						readTaskSource?.TrySetResult();
					}
				}
			}

			public async ValueTask<int> Read(Memory<byte> buffer)
			{
				if (i >= current.Length)
				{

					bool queueHadAnything;
					lock (lockobj)
					{
						queueHadAnything = q.TryDequeue(out current);
						if (queueHadAnything)
						{
							i = 0;
						}
						else
						{
							//wait for write
							readTaskSource = new();
						}
					}
					if (!queueHadAnything)
					{
						await readTaskSource.Task;
						lock (lockobj)
							current = q.Dequeue();
						i = 0;
					}
				}

				//now we're good
				var len = Math.Min(buffer.Length, current.Length - i);
				current.Slice(i, len).CopyTo(buffer);
				i += len;
				return len;
			}
		}

		public static (FakeNetworkStream, FakeNetworkStream) Create()
		{
			var a = new ByteStream();
			var b = new ByteStream();
			return (new(a, b), new(b, a));
		}

		private FakeNetworkStream(ByteStream read, ByteStream write)
		{
			this.read = read;
			this.write = write;
		}
		ByteStream read;
		ByteStream write;

		public override bool CanRead => true;

		public override bool CanSeek => false;

		public override bool CanWrite => true;

		public override long Length => throw new NotSupportedException();

		public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

		public override void Flush() { }

		public override int Read(byte[] buffer, int offset, int count)
		{
			using var sync = new SynchronizationContextSwap.SynchronizationContextSwap();
			var t = ReadAsync(new(buffer, offset, count));
			if (t.IsCompleted)
				return t.Result;
			else
				return t.AsTask().Result;
		}

		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			return ReadAsync(new(buffer, offset, count), cancellationToken).AsTask();
		}

		public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			return read.Read(buffer);
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			var t = WriteAsync(new(buffer, offset, count));
			if (!t.IsCompleted)
				t.AsTask().Wait();
		}

		public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
		{
			write.Write(buffer);
			return ValueTask.CompletedTask;
		}
	}
}
