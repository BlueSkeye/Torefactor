using System;
using System.Text;

using TorNet.Interop;

namespace TorNet.Cryptography
{
    internal static class Base16
    {
        internal static byte[] Decode(string input)
        {
            return Decode(input, input.Length);
        }

        internal static byte[] Decode(string input, int inputSize)
        {
            return EncodingBase.Decode(input, Crypt32.CrypBinaryFlags.AnyHexadecimal,
                inputSize);
        }

        internal static string Encode(byte[] input)
        {
            return Encode(input, ASCIIEncoding.ASCII);
        }

        internal static string Encode(byte[] input, Encoding encoding)
        {
            return EncodingBase.Encode(input,
                Crypt32.CrypBinaryFlags.RawHexadecimal | Crypt32.CrypBinaryFlags.NoCRLF,
                encoding);
        }
    }
}
