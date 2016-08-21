using System;
using TorNet.Interop;

namespace TorNet.Cryptography
{
    internal class Randomizer : IDisposable
    {
        internal Randomizer(CryptoProvider provider)
        {
            _provider = provider;
        }

        ~Randomizer()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) { GC.SuppressFinalize(this); }
            return;
        }

    //    internal get_random<T>()
    //    {
    //        T result;
    //        CryptGenRandom(_provider.Handle,
    //          sizeof(T),
    //          (BYTE*)&result);
    //        return result;
    //    }

    //    template<typename T>
    //    T
    //get_random(
    //    T max
    //  )
    //    {
    //        return get_random() % max;
    //    }

        internal byte[] get_random_bytes(int byte_count)
        {
            byte[] result = new byte[byte_count];
            get_random_bytes(result);
            return result;
        }

        internal void get_random_bytes(byte[] output)
        {
            Advapi32.CryptGenRandom(_provider.Handle, output.Length, output);
        }

        internal ulong GetUInt64()
        {
            byte[] rawData = new byte[sizeof(ulong)];
            get_random_bytes(rawData);
            ulong result = 0;
            for(int index = 0; index < sizeof(ulong); index++) {
                result *= 256;
                result += rawData[index];
            }
            return result;
        }

        private CryptoProvider _provider;
    }
}
