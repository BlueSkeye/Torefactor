using System;
using System.Runtime.InteropServices;
using TorNet.Interop;

namespace TorNet.Cryptography
{
    internal class CryptoProvider : IDisposable
    {
        private CryptoProvider()
        {
            _providerHandle = IntPtr.Zero;
            init();
        }

        ~CryptoProvider()
        {
            Dispose(false);
        }

        internal static CryptoProvider Instance
        {
            get { return _instance; }
        }

        private void init()
        {
            Advapi32.CryptAcquireContext(out _providerHandle, null,
                Advapi32.RsaAesProviderName, Advapi32.RsaAesProvider,
                Advapi32.ContextCreationFlags.VerifyContect);
        }

        public void Dispose()
        {
            Dispose(true);
        }

        private void Dispose(bool disposing)
        {
            if (disposing) { GC.SuppressFinalize(this); }
            Advapi32.CryptReleaseContext(_providerHandle, 0);
            _providerHandle = IntPtr.Zero;
            return;
        }

        internal IntPtr Handle
        {
            get { return _providerHandle; }
        }

        internal AES CreateAes()
        {
            return new AES(this);
        }

        internal SHA1 CreateSha1()
        {
            return new SHA1(this);
        }

        internal RSA CreateRSA()
        {
            return new RSA(this);
        }

        internal Randomizer CreateRandom()
        {
            return new Randomizer(this);
        }

        internal static IntPtr ImportRsaPublicKey(byte[] rawData)
        {
            CryptoProvider provider = new CryptoProvider();
            IntPtr nativeStructure = IntPtr.Zero;
            int nativeStructureSize = 0;
            try {
                if (!Advapi32.CryptDecodeObjectEx(CertificateEncodingType.X509Asn,
                    InteropHelpers.GetWellKnownOIDPointer(InteropHelpers.WellKnownOIDs.X509PublicKeyInfo),
                    rawData, rawData.Length, Advapi32.EncodingFlags.AllocateMemory, IntPtr.Zero,
                    ref nativeStructure, ref nativeStructureSize))
                {
                    throw new CryptographyException((WinErrors)(uint)Marshal.GetLastWin32Error());
                }
                IntPtr result = IntPtr.Zero;
                if (!Crypt32.CryptImportPublicKeyInfo(provider.Handle, CertificateEncodingType.X509Asn,
                    nativeStructure, out result))
                {
                    throw new CryptographyException((WinErrors)(uint)Marshal.GetLastWin32Error());
                }
                return result;
            }
            finally {
                if (IntPtr.Zero != nativeStructure) {
                    if (IntPtr.Zero != Kernel32.LocalFree(nativeStructure)) {
                        throw new InteropException(Marshal.GetLastWin32Error());
                    }
                }
                provider.Dispose();
            }
        }

        internal static CryptoProvider _instance = new CryptoProvider();
        // TODO : Make this a safe handle.
        private IntPtr /* HCRYPTPROV */ _providerHandle;
    }
}
