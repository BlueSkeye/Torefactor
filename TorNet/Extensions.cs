using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;

using TorNet.Cryptography;

namespace TorNet
{
    internal static class Extensions
    {
        internal static byte[] DecodeHexadecimalEncodedString(this string data, bool throwOnError = true)
        {
            bool errorEncountered = false;

            if (null == data) { throw new ArgumentNullException(); }
            if (0 == (data.Length % 2)) {
                int bytesCount = data.Length / 2;
                byte[] result = new byte[bytesCount];
                for(int index = 0; index < bytesCount; index++) {
                    byte extractedByte;
                    if (!byte.TryParse(data.Substring(2 * index, 2), NumberStyles.AllowHexSpecifier, null, out extractedByte)) {
                        errorEncountered = true;
                        break;
                    }
                    result[index] = extractedByte;
                }
                if (!errorEncountered) { return result; }
            }
            if (!throwOnError) { return null; }
            throw new ParsingException("Expecting an hexadcimal encoded string. Found '{0}'.", data);
        }

        internal static T GetRandom<T>(this List<T> from)
        {
            if (null == from) { throw new ArgumentNullException(); }
            if (0 == from.Count) { throw new ArgumentException(); }
            using (Randomizer randomizer = new Randomizer(CryptoProvider.Instance)) {
                return from[(int)(randomizer.GetUInt64() % (ulong)from.Count)];
            }
        }

        internal static bool IsEmpty<K,V>(this Dictionary<K,V> candidate)
        {
            return (0 == candidate.Count);
        }

        internal static bool IsEmpty<K, V>(this SortedList<K, V> candidate)
        {
            return (0 == candidate.Count);
        }

        internal static bool IsInRange(this IntPtr candidate, IntPtr lowerBound, IntPtr upperBound)
        {
            return (((ulong)candidate.ToInt64() >= (ulong)lowerBound.ToInt64())
                && ((ulong)candidate.ToInt64() <= (ulong)upperBound.ToInt64()));
        }

        internal static V LastValue<K, V>(this SortedList<K, V> candidate)
        {
            IList<V> values = candidate.Values;
            int lastIndex = values.Count - 1;
            return (0 > lastIndex) ? default(V) : values[lastIndex];
        }

        internal static int SecondsSinceEpoch(this DateTime dateTime)
        {
            return (int)((Epoch - dateTime).TotalSeconds);
        }

        internal static byte[] Slice(this byte[] buffer, int begin)
        {
            return buffer.Slice(begin, buffer.Length);
        }

        internal static byte[] Slice(this byte[] buffer, int begin, int end)
        {
            if (-1 == end) { end = buffer.Length; }
            byte[] result = new byte[end - begin + 1];
            Buffer.BlockCopy(buffer, begin, result, 0, result.Length);
            return result;
        }

        internal static byte[] SwapEndianness(this byte[] data)
        {
            return SwapEndianness(data, data.Length);
        }

        internal static byte[] SwapEndianness(this byte[] data, int length)
        {
            byte[] result = new byte[length];
            for (int k = 0; k < length; k++) {
                result[k] = data[length - k - 1];
            }
            return result;
        }

        internal static ushort SwapEndianness(this ushort data)
        {
            return (ushort)(((data % 256) * 256) + (data / 256));
        }

        internal static uint SwapEndianness(this uint data)
        {
            uint result = 0;
            for(int index = 0; index < sizeof(uint); index++) {
                result *= 256;
                result += data % 256;
                data /= 256;
            }
            return result;
        }

        internal static ushort ToUInt16(this byte[] data)
        {
            return (ushort)((data[1] * 256) + data[0]);
        }

        internal static uint ToUInt32(this byte[] data)
        {
            uint result = data[3];
            result = (256 * result) + data[2];
            result = (256 * result) + data[1];
            result = (256 * result) + data[0];
            return result;
        }

        internal static ulong ToUInt64(this byte[] data)
        {
            ulong result = data[7];
            result = (256 * result) + data[6];
            result = (256 * result) + data[5];
            result = (256 * result) + data[4];
            result = (256 * result) + data[3];
            result = (256 * result) + data[2];
            result = (256 * result) + data[1];
            result = (256 * result) + data[0];
            return result;
        }

        internal static byte[] ToArray(this uint data)
        {
            byte[] result = new byte[sizeof(uint)];
            for(int index = 0; index < sizeof(uint); index++) {
                result[index] = (byte)(data % 256);
                data /= 256;
            }
            return result;
        }

        internal static void Zeroize(this byte[] target)
        {
            Zeroize(target, 0);
        }

        internal static void Zeroize(this byte[] target, int offset)
        {
            Zeroize(target, offset, target.Length);
        }

        internal static void Zeroize(this byte[] target, int offset, int length)
        {
            for(int index = offset; index < length; index++) {
                target[index] = 0;
            }
        }

        internal static void Zeroize(this uint[] target)
        {
            Zeroize(target, 0);
        }

        internal static void Zeroize(this uint[] target, int offset)
        {
            Zeroize(target, 0, target.Length);
        }

        internal static void Zeroize(this uint[] target, int offset, int size)
        {
            for(int index = offset; index < size; index++) {
                target[index] = 0;
            }
        }

        internal static void Zeroize(this IntPtr target, int size)
        {
            int offset = 0;
            while(sizeof(long) < size) {
                Marshal.WriteInt64(target, offset, 0);
                offset += sizeof(long);
                size -= sizeof(long);
            }
            if (sizeof(int) < size) {
                Marshal.WriteInt32(target, offset, 0);
                offset += sizeof(int);
                size -= sizeof(int);
            }
            while(0 < size) {
                Marshal.WriteByte(target, offset, 0);
                offset += sizeof(byte);
                size -= sizeof(byte);
            }
            return;
        }

        private static readonly DateTime Epoch = new DateTime(1970, 1, 1);
    }
}
