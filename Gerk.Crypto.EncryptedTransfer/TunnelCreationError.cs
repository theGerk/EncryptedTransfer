using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Gerk.Crypto.EncryptedTransfer
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
		ConnectionLost,
		RemoteNeedsUpgrade,
		INeedUpgrade,
		RemotePublicKeyToLarge,
	}
}
