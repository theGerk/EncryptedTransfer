using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Gerk.Crypto.EncryptedTransfer
{
	/// <summary>
	/// Error code for errors that happen during the tunnel creation
	/// </summary>
	/// <seealso cref="Tunnel.CreateInitiator{Id}(Stream, RSACryptoServiceProvider, IEnumerable{Id}, System.Func{Id, byte[]}, out Id, out TunnelCreationError, bool)"/>
	/// <seealso cref="Tunnel.CreateResponder{Id}(Stream, RSACryptoServiceProvider, IEnumerable{Id}, System.Func{Id, byte[]}, out Id, out TunnelCreationError, bool)"/>
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
		/// <summary>
		/// Connection was lost durring establishment.
		/// </summary>
		ConnectionLost,
		/// <summary>
		/// The other side of the tunnel is on a previous version to you, and should upgrade.
		/// </summary>
		RemoteNeedsUpgrade,
		/// <summary>
		/// The other side of the tunnel is on a later version from you, and you should upgrade.
		/// </summary>
		INeedUpgrade,
	}
}
