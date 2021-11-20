using Gerk.AsyncThen;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Gerk.Crypto.EncryptedTransfer.Test
{
	public static class UnitTest1
	{
		public static ushort reciver(Stream stream, byte[] local, byte[] remote, string send)
		{
			using var rsa = new RSACryptoServiceProvider();
			rsa.ImportCspBlob(local);
			using var tunnel = Tunnel.CreateResponder(stream, rsa, new byte[][] { remote }, out _, out var err);
			if (err != TunnelCreationError.NoError)
				throw new Exception(err.ToString());
			using var reader = new BinaryReader(tunnel);
			using var writer = new BinaryWriter(tunnel);

			writer.Write(send);
			tunnel.FlushWriter();
			var line = reader.ReadUInt16();
			tunnel.FlushReader();
			return line;
		}

		public static string sender(Stream stream, byte[] local, byte[] remote, ushort send)
		{
			using var rsa = new RSACryptoServiceProvider();
			rsa.ImportCspBlob(local);
			using var tunnel = Tunnel.CreateInitiator(stream, rsa, new byte[][] { remote }, out _, out var err);
			if (err != TunnelCreationError.NoError)
				throw new Exception(err.ToString());
			using var reader = new BinaryReader(tunnel);
			using var writer = new BinaryWriter(tunnel);
			writer.Write(send);
			tunnel.FlushWriter();
			var line = reader.ReadString();
			tunnel.FlushReader();
			return line;
		}

		[Fact]
		public static async Task Maintest()
		{
			TcpListener server = new TcpListener(System.Net.IPAddress.Loopback, 0);
			server.Start();
			TcpClient client = new TcpClient();
			client.Connect((server.LocalEndpoint as System.Net.IPEndPoint));

			using var c = new RSACryptoServiceProvider();
			using var d = new RSACryptoServiceProvider();
			using var sha = SHA256.Create();

			const ushort msg = 1;
			const string response = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";



			var sendTask = Task.Run(() => sender(client.GetStream(), c.ExportCspBlob(true), SHA256.HashData(d.ExportCspBlob(false)), msg));
			var reciveTask = Task.Run(() => reciver(server.AcceptTcpClient().GetStream(), d.ExportCspBlob(true), SHA256.HashData(c.ExportCspBlob(false)), response));
			await Task.WhenAll(sendTask, reciveTask);
			Assert.True(await sendTask == response);
			Assert.True(await reciveTask == msg);
		}

		[Fact]
		public static async Task FlushwriterRepeatedly()
		{

		}
	}
}