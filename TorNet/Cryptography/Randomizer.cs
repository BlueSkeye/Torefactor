using TorNet.Interop;

namespace TorNet.Cryptography
{
    internal class Randomizer
    {
        internal Randomizer(CryptoProvider crypto_provider)
        {
            _provider = crypto_provider;
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

        private CryptoProvider _provider;
    }
}
