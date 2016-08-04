using System;
using System.Runtime.InteropServices;
using System.Text;

using TorNet.Interop;

namespace TorNet.Cryptography
{
    internal static class EncodingBase
    {
        internal static byte[] Decode(string input, Crypt32.CrypBinaryFlags flags,
            int inputSize)
        {
            int output_size = 0;
            byte[] result = null;
            _Decode(input, input.Length, ref result, ref output_size, flags, true, false);
            result = new byte[output_size];
            _Decode(input, input.Length, ref result, ref output_size, flags, false, false);
            return result;
        }

        private static void _Decode(string input, int input_size, ref byte[] output,
            ref int output_size, Crypt32.CrypBinaryFlags flags, bool get_only_size,
            bool alloc_buffer)
        {
            if (get_only_size) {
                output_size = 0;
                output = null;
            }
            else {
                if (alloc_buffer) {
                    output = new byte[output_size];
                }
            }
            int pdwSkip;
            int pdwFlags;

            if (!Crypt32.CryptStringToBinary(input, input_size,
                Crypt32.CrypBinaryFlags.AnyHexadecimal, IntPtr.Zero,
                ref output_size, out pdwSkip, out pdwFlags))
            {
                int nativeError = Marshal.GetLastWin32Error();
                throw new InteropException(string.Format("ERROR {0}", nativeError);
            }
        }

        internal static string Encode(byte[] input, Crypt32.CrypBinaryFlags flags,
            Encoding encoding)
        {
            int output_size = 0;
            byte[] result = null;
            _Encode(input, input.Length, ref result, ref output_size, flags, true, false);
            result = new byte[output_size];
            _Encode(input, input.Length, ref result, ref output_size, flags, false, false);
            return encoding.GetString(result);
        }

        private static void _Encode(byte[] input, int input_size, ref byte[] output,
            ref int output_size, Crypt32.CrypBinaryFlags flags, bool get_only_size,
            bool alloc_buffer)
        {
            if (get_only_size) {
                output_size = 0;
                output = null;
            }
            else {
                if (alloc_buffer) {
                    output = new byte[output_size];
                }
            }
            if (!Crypt32.CryptBinaryToString(input, input_size, flags, output, ref output_size)) {
                throw new InteropException();
            }
        }
    }
}
