using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Gerk.Crypto.EncryptedTransfer;
using Xunit;

namespace Net6_Test
{
	public static class SafeTunnelTest
	{
		public static O RunSide<O>(Stream stream, byte[] local, byte[] remote, Action<BinaryWriter> write, Func<BinaryReader, O> read)
		{
			using var rsa = new RSACryptoServiceProvider();
			rsa.ImportCspBlob(local);
			using var rawtunnel = Tunnel.Create(stream, rsa, new byte[][] { remote }, out _, out var err, out var errm);
			if (err != TunnelCreationError.NoError)
				throw new Exception(errm);
			using var tunnel = new SafeTunnel(rawtunnel);
			using var reader = new BinaryReader(tunnel);
			using var writer = new BinaryWriter(tunnel);
			write(writer);
			return read(reader);
		}


		[Fact]
		public static async Task Maintest()
		{
			TcpListener server = new TcpListener(System.Net.IPAddress.Loopback, 0);
			server.Start();
			TcpClient client = new TcpClient();
			client.Connect((System.Net.IPEndPoint)server.LocalEndpoint);

			using var c = new RSACryptoServiceProvider();
			using var d = new RSACryptoServiceProvider();
			using var sha = SHA256.Create();

			const ushort msg = 1;
			const string response = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";



			var sendTask = Task.Run(() => RunSide(client.GetStream(), c.ExportCspBlob(true), SHA256.HashData(d.ExportCspBlob(false)), bw => bw.Write(msg), br => br.ReadString()));
			var reciveTask = Task.Run(() => RunSide(server.AcceptTcpClient().GetStream(), d.ExportCspBlob(true), SHA256.HashData(c.ExportCspBlob(false)), bw => bw.Write(response), br => br.ReadUInt16()));
			await Task.WhenAll(sendTask, reciveTask);
			Assert.Equal(response, await sendTask);
			Assert.Equal(msg, await reciveTask);
		}
	}
}
