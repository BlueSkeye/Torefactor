using System;
using System.Runtime.InteropServices;

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

        private void destroy()
        {
            Advapi32.CryptDestroyHash(_hash);
        }

        internal SHA1 Duplicate()
        {
            return new SHA1(_provider, this);
        }

        private void duplicate_internal(SHA1 other)
        {
            Advapi32.CryptDuplicateHash(other._hash, IntPtr.Zero, 0, out _hash);
        }

        internal byte[] GetHash()
        {
            byte[] result = new byte[20];
            GetHash(result);
            return result;
        }

        private void GetHash(byte[] into)
        {
            int hashSize = into.Length;
            IntPtr nativeBuffer = IntPtr.Zero;
            try {
                nativeBuffer = Marshal.AllocCoTaskMem(hashSize);
                if (!Advapi32.CryptGetHashParam(_hash, Advapi32.HP_HASHVAL, nativeBuffer,
                    ref hashSize, 0))
                {
                    throw new CryptographyException((WinErrors)Marshal.GetLastWin32Error());
                }
                Marshal.Copy(nativeBuffer, into, 0, hashSize);
            }
            finally {
                if(IntPtr.Zero != nativeBuffer) { Marshal.FreeCoTaskMem(nativeBuffer); }
            }
        }

        internal static byte[] Hash(byte[] input)
        {
            SHA1 hasher = CryptoProvider.Instance.CreateSha1();
            hasher.Update(input);
            return hasher.GetHash();
        }

        internal static byte[] Hash(byte[] input, out IntPtr hHasher)
        {
            SHA1 hasher = CryptoProvider.Instance.CreateSha1();
            hasher.Update(input);
            hHasher = hasher._hash;
            return hasher.GetHash();
        }

        internal void init()
        {
            Advapi32.CryptCreateHash(_provider.Handle, Advapi32.CALG_SHA1, IntPtr.Zero, 0, out _hash);
        }

        internal void Update(byte[] input)
        {
            bool result = Advapi32.CryptHashData(_hash, input, input.Length, 0);
        }

        private CryptoProvider _provider;
        private IntPtr /* HCRYPTHASH */ _hash;
    }
}
