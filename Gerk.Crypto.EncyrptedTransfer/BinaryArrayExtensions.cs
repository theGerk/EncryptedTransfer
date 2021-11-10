using System;
using System.Runtime.InteropServices;

namespace Gerk.Crypto.EncyrptedTransfer
{
	internal static class ByteArrayExtensions
    {
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int memcmp(byte[] b1, byte[] b2, UIntPtr count);

        public static bool SequenceEquals(this byte[] b1, byte[] b2)
        {
            if (b1 == b2) return true; //reference equality check

            if (b1 == null || b2 == null || b1.Length != b2.Length) return false;

            return memcmp(b1, b2, new UIntPtr((uint)b1.Length)) == 0;
        }
    }
}
