using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;

namespace TorNet
{
    internal static class Helpers
    {
        static Helpers()
        {
            DecompressionTestFilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CompressedSample.z");
            return;
        }

        internal static bool AreEquals(byte[] x, byte[] y, int length)
        {
            return AreEquals(x, 0, y, 0, length);
        }

        internal static bool AreEquals(byte[] x, int xOffset, byte[] y, int yOffset, int length)
        {
            if (length > (x.Length - xOffset + 1)) { return false; }
            if (length > (y.Length - yOffset + 1)) { return false; }
            while (0 < length) {
                if (x[xOffset++] != y[yOffset++]) { return false; }
            }
            return true;
        }

        internal static T[] Extend<T>(T[] reallocated, int newSize)
        {
            if (null == reallocated) { throw new ArgumentNullException(); }
            if (reallocated.Length > newSize) { throw new ArgumentOutOfRangeException(); }
            T[] result = new T[newSize];
            Buffer.BlockCopy(reallocated, 0, result, 0, reallocated.Length);
            return result;
        }

        /// <summary>Asynchronously retrieve an HTTP url.
        /// WARNING : This method MUST NOT be used except for initial consensus
        /// download.</summary>
        /// <param name="hostName"></param>
        /// <param name="port"></param>
        /// <param name="path"></param>
        /// <returns></returns>
        internal static async Task<byte[]> HttpGetBinaryContent(string hostName, int port,
            string path)
        {
            using (HttpClient client = new HttpClient() {
                BaseAddress = new Uri(string.Format("http://{0}:{1}/", hostName, port))
                })
            {
                HttpResponseMessage response = await client.GetAsync(path);
                if (!response.IsSuccessStatusCode) {
                    throw new ApplicationException();
                }
                return await response.Content.ReadAsByteArrayAsync();
            }
        }

        /// <summary>Asynchronously retrieve an HTTP url.
        /// WARNING : This method MUST NOT be used except for initial consensus
        /// download.</summary>
        /// <param name="hostName"></param>
        /// <param name="port"></param>
        /// <param name="path"></param>
        /// <returns></returns>
        internal static async Task<string> HttpGetStringContent(string hostName, int port,
            string path)
        {
            using (HttpClient client = new HttpClient() {
                BaseAddress = new Uri(string.Format("http://{0}:{1}/", hostName, port))
                })
            {
                HttpResponseMessage response = await client.GetAsync(path);
                if (!response.IsSuccessStatusCode) {
                    throw new ApplicationException();
                }
                return await response.Content.ReadAsStringAsync();
            }
        }

        internal static bool IsNullOrEmpty<X>(List<X> candidate)
        {
            if (null == candidate) { return true; }
            if (0 == candidate.Count) { return true; }
            return false;
        }

        internal static bool IsNullOrEmpty<X>(X[] candidate)
        {
            if (null == candidate) { return true; }
            if (0 == candidate.Length) { return true; }
            return false;
        }

        //template<
        //  typename ITERATOR_TYPE,
        //  typename T,
        //  typename COMPARE_TYPE
        //>
        internal delegate bool BoundComparatorDelegate<T, V>(T candidate, V value);

        internal static int lower_bound<T, V>(IList<T> from,
          //ITERATOR_TYPE first,
          //ITERATOR_TYPE last,
          V value,
          BoundComparatorDelegate<T,V> comp)
        {
            // ITERATOR_TYPE it;
            // ptrdiff_t step;
            int count = from.Count;
            int position = 0;

            while (count > 0) {
                T it = from[position];
                // it = first;
                int step = count / 2;
                int pivot = position + step;
                if (comp(it, value)) {
                    position = pivot + 1;
                    count -= step + 1;
                }
                else {
                    count = step;
                }
            }
            return position;
        }

        internal static void Resize(ref byte[] buffer, int new_size)
        {
            if (buffer.Length == new_size) { return; }
            if (new_size < buffer.Length) {
                byte[] result = new byte[new_size];
                Buffer.BlockCopy(buffer, 0, result, 0, new_size);
                buffer = result;
                return;
            }
            if (new_size < buffer.Length) {
                byte[] result = new byte[new_size];
                Buffer.BlockCopy(buffer, 0, result, 0, new_size);
                buffer = result;
                return;
            }
        }

        internal static int RoundUp(int value, int to)
        {
            return ((value + to - 1) / to) * to;
        }

        internal static void Swap<T>(ref T lhs, ref T rhs)
        {
            T temp = lhs;
            lhs = rhs;
            rhs = temp;
        }

        internal static byte[] Uncompress(byte[] compressedContent)
        {
            // ZLib format is not supported as is by managed decompression stream.
            // We need to strip the ZLib header and footer checksum.
            // TODO : Add some additional checks such as checksum verification and
            // header decoding here.
            byte[] strippedBuffer = new byte[compressedContent.Length - 6];
            Buffer.BlockCopy(compressedContent, 2, strippedBuffer, 0, strippedBuffer.Length);
            using (MemoryStream input = new MemoryStream(strippedBuffer)) {
                using (MemoryStream output = new MemoryStream()) {
                    using (DeflateStream deflater = new DeflateStream(input, CompressionMode.Decompress)) {
                        deflater.CopyTo(output);
                        output.Flush();
                        return output.ToArray();
                    }
                }
            }
        }

        internal static void WTF()
        {
            throw new InternalErrorException();
        }

        internal static readonly string DecompressionTestFilePath;
    }
}
