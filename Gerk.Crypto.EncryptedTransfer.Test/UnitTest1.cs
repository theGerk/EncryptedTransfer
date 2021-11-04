using Gerk.AsyncThen;
using Gerk.Crypto.EncyrptedTransfer;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
		public static int startbreaking = 0;

		public string reciver(Stream stream, RSAParameters local, RSAParameters remote, string send)
		{
			using var rsa = new RSACryptoServiceProvider();
			rsa.ImportParameters(local);
			using var tunnel = Tunnel.CreateResponder(stream, new RSAParameters[] { remote }, rsa, out var err);
			if (err != TunnelCreationError.NoError)
				throw new Exception(err.ToString());
			startbreaking++;
			using var reader = new BinaryReader(tunnel);
			using var writer = new BinaryWriter(tunnel);
			writer.Write(send);
			tunnel.FlushWriter();
			//var line = reader.ReadString();
			return null;
		}

		public string sender(Stream stream, RSAParameters local, RSAParameters remote, string send)
		{
			using var rsa = new RSACryptoServiceProvider();
			rsa.ImportParameters(local);
			using var tunnel = Tunnel.CreateInitiator(stream, new RSAParameters[] { remote }, rsa, out var err);
			if (err != TunnelCreationError.NoError)
				throw new Exception(err.ToString());
			startbreaking++;
			using var reader = new BinaryReader(tunnel);
			using var writer = new BinaryWriter(tunnel);
			//writer.Write(send);
			//tunnel.FlushWriter();
			var line = reader.ReadString();
			return line;
		}

		[Fact]
		public async Task Test1()
		{
			var (a, b) = FakeNetworkStream.Create();
			using var c = new RSACryptoServiceProvider();
			using var d = new RSACryptoServiceProvider();
			const string msg = "Hello world!";
			const string response = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
			var sendTask = Task.Run(() => sender(a, c.ExportParameters(true), d.ExportParameters(false), msg));
			var reciveTask = Task.Run(() => reciver(b, d.ExportParameters(true), c.ExportParameters(false), response));
			await Task.WhenAll(sendTask, reciveTask);
			Assert.True(await sendTask == response);
			//Assert.True(await reciveTask == msg);
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
