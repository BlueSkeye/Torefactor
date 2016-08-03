using System;
using System.Collections.Generic;
using System.Text;

namespace TorNet.Cryptography
{
    internal static class Base32
    {
        // RFC 4648 alphabet.
        internal static int get_encode_length(int bytes)
        {
            int bits = bytes * 8;
            int length = bits / 5;

            if ((bits % 5) > 0) {
                length++;
            }
            return length;
        }

        internal static int get_decode_length(int bytes)
        {
            int bits = bytes * 5;
            int length = bits / 8;
            return length;
        }

        private static void encode_chunk(byte[/*5*/] input, int inputOffset,
            byte[/*8*/] output)
        {
            ulong buffer = 0;
            for (int i = 0; i< 5; i++) {
                buffer = (buffer << 8) | input[i + inputOffset];
            }
            for (int i = 7; i >= 0; i--) {
                buffer <<= (24 + (7 - i) * 5);
                buffer >>= (24 + (7 - i) * 5);
                byte c = (byte)(buffer >> (i * 5));
                output[7 - i] = (byte)(c + (c< 0x1a ? 'a' : ('2' - 0x1a)));
            }
        }

        private static void decode_chunk(byte[/*8*/] input, int inputOffset, byte[/*5*/] output)
        {
            ulong buffer = 0;

            for (int i = 0; i < 8; i++) {
                buffer = (buffer << 5) | (byte)(input[i + inputOffset] - (input[i + inputOffset] >= 'a' ? 'a' : ('2' - 0x1a)));
            }
            for (int j = 4; j >= 0; j--) {
                output[4 - j] = (byte)(buffer >> (j * 8));
            }
        }

        internal static string encode(byte[] input)
        {
            List<byte> output = new List<byte>();

            // get quotient & remainder.
            int q = input.Length / 5;
            int r = input.Length % 5;

            byte[] out_chunk_buffer = new byte[8];
            for (int j = 0; j < q; j++) {
                encode_chunk(input, j * 5, out_chunk_buffer);
                output.AddRange(out_chunk_buffer);
            }
            byte[] out_padding_buffer = new byte[get_encode_length(r)];
            for (int i = 0; i < out_padding_buffer.Length; i++) {
                out_padding_buffer[i] = input[input.Length - r + i];
            }
            encode_chunk(out_padding_buffer, 0, out_chunk_buffer);
            output.AddRange(out_chunk_buffer);
            return ASCIIEncoding.ASCII.GetString(output.ToArray());
        }

        internal static byte[] decode(string input)
        {
            byte[] data = ASCIIEncoding.ASCII.GetBytes(input);
            List<byte> output = new List<byte>();
            // get quotient & remainder.
            int q = input.Length / 8;
            int r = input.Length % 8;
            byte[] out_chunk_buffer = new byte[5];
            for (int j = 0; j < q; j++) {
                decode_chunk(data, j * 8, out_chunk_buffer);
                output.AddRange(out_chunk_buffer);
            }
            byte[] out_padding_buffer = new byte[8];
            for (int i = 0; i < r; i++) {
                out_padding_buffer[i] = data[input.Length - r + i];
            }
            decode_chunk(out_padding_buffer, 0, out_chunk_buffer);
            output.AddRange(out_chunk_buffer);
            return output.ToArray();
        }
    }
}
