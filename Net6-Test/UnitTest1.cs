using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace Gerk.Crypto.EncryptedTransfer.Test
{
	public static class UnitTest1
	{
		//public static async Task<(Tunnel, Tunnel)> createPair()
		//{
		//	TcpListener server = new TcpListener(System.Net.IPAddress.Loopback, 0);
		//	server.Start();
		//	TcpClient client = new TcpClient();
		//	client.Connect((System.Net.IPEndPoint)server.LocalEndpoint);

		//	using var c = new RSACryptoServiceProvider();
		//	using var d = new RSACryptoServiceProvider();
		//	using var sha = SHA256.Create();

		//	return (
		//		await Task.Run(() => Tunnel.Create(client.GetStream(), c, new byte[][] { SHA256.HashData(d.ExportCspBlob(false)) }, out var _, out var err1, out var errm1),
		//		await Task.Run(() => Tunnel.Create(client.GetStream(), d, new byte[][] { SHA256.HashData(c.ExportCspBlob(false)) }, out var _, out var eer2, out var errm2)
		//	);
		//}

		public static O RunSide<O>(Stream stream, byte[] local, byte[] remote, Action<BinaryWriter> write, Func<BinaryReader, O> read)
		{
			using var rsa = new RSACryptoServiceProvider();
			rsa.ImportCspBlob(local);
			using var tunnel = Tunnel.Create(stream, rsa, new byte[][] { remote }, out _, out var err, out var errm);
			if (err != TunnelCreationError.NoError)
				throw new Exception(errm);
			using var reader = new BinaryReader(tunnel);
			using var writer = new BinaryWriter(tunnel);
			write(writer);
			tunnel.FlushWriter();
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
			Assert.True(await sendTask == response);
			Assert.True(await reciveTask == msg);
		}
	}
}