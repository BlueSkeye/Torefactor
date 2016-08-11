using System;

using TorNet.Interop;

namespace TorNet.Cryptography
{
    internal class CryptoProvider
    {
        private CryptoProvider()
        {
            _providerHandle = IntPtr.Zero;
            init();
        }

        ~CryptoProvider()
        {
            destroy();
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

        private void destroy()
        {
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

        internal static CryptoProvider _instance = new CryptoProvider();
        // TODO : Make this a safe handle.
        private IntPtr /* HCRYPTPROV */ _providerHandle;
    }
}
