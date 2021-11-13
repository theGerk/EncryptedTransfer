using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Gerk.Crypto.EncyrptedTransfer
{
	/// <summary>
	/// Something that has a public key hash
	/// </summary>
	public interface IHasPublicKeySha
	{
		/// <summary>
		/// Gets the SHA256 has of a public key when encoded as a CspBlob associated with this object.
		/// </summary>
		/// <seealso cref="RSACryptoServiceProvider.ExportCspBlob(bool)"/>
		/// <returns>Sha256 hash of a public key encoded as a CspBlob.</returns>
		byte[] GetPublicKeySha();
	}
}
