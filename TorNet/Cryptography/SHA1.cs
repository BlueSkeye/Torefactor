using System;

using TorNet.Interop;

namespace TorNet.Cryptography
{
    internal class SHA1
    {
        internal SHA1(CryptoProvider crypto_provider)
        {
            _provider = crypto_provider;
            init();
        }

        internal SHA1(CryptoProvider crypto_provider, SHA1 other)
        {
            _provider = crypto_provider;
            duplicate_internal(other);
        }

        ~SHA1()
        {
            destroy();
        }

        internal void init()
        {
            Advapi32.CryptCreateHash(_provider.Handle, Advapi32.CALG_SHA1, IntPtr.Zero, 0, out _hash);
        }

        private void destroy()
        {
            Advapi32.CryptDestroyHash(_hash);
        }

        internal void Update(byte[] input)
        {
            bool result = Advapi32.CryptHashData(_hash, input, input.Length, 0);
        }

        private void get(byte[] output)
        {
            int hash_size = 20;
            Advapi32.CryptGetHashParam(_hash, Advapi32.HP_HASHVAL, ref output,
                ref hash_size, 0);
        }

        internal byte[] get()
        {
            byte[] result = new byte[20];
            get(result);
            return result;
        }

        internal SHA1 Duplicate()
        {
            return new SHA1(_provider, this);
        }

        private void duplicate_internal(SHA1 other)
        {
            Advapi32.CryptDuplicateHash(other._hash, IntPtr.Zero, 0, out _hash);
        }

        internal static byte[] Hash(byte[] input)
        {
            SHA1 md = CryptoProvider.Instance.CreateSha1();
            md.Update(input);
            return md.get();
        }

        private CryptoProvider _provider;
        private IntPtr /* HCRYPTHASH */ _hash;
    }
}
