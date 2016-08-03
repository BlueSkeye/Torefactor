using System;
using System.Runtime.InteropServices;

using TorNet.Interop;

namespace TorNet.Cryptography
{
    internal class AES
    {
        internal AES(CryptoProvider crypto_provider)
        {
            this._provider = crypto_provider;
            this._key = IntPtr.Zero;
        }

        ~AES()
        {
            destroy();
        }

        internal void init(Mode aes_mode, KeySize aes_key_size, byte[] key)
        {
            _mode = aes_mode;
            switch (aes_key_size) {
                case KeySize.Aes128:
                    _key_size = 16;
                    break;
                case KeySize.Aes192:
                    _key_size = 24;
                    break;
                case KeySize.Aes256:
                    _key_size = 32;
                    break;
                default:
                    _key_size = 0;
                    break;
            }
            _counter.Zeroize();
            _counter_out.Zeroize();
            _keystream_pointer = 0xFFFF;
            // initialize WinCrypt AES-128 key.
            ms_aes_key key_blob = new ms_aes_key();
            key_blob.header.bType = BlobType.PlainText;
            key_blob.header.bVersion = CurrentBlobVersion;
            key_blob.header.reserved = 0;
            key_blob.header.aiKeyAlg = (uint)aes_key_size;
            key_blob.size = _key_size;
            Buffer.BlockCopy(key, 0, key_blob.key, 0, (int)key_blob.size);
            int nativeKeySize;
            IntPtr nativeKey = key_blob.Serialize(out nativeKeySize);
            try {
                bool result = Crypt32.CryptImportKey(_provider.Handle, nativeKey,
                    nativeKeySize, IntPtr.Zero, 0, out _key);
            }
            finally { Marshal.FreeCoTaskMem(nativeKey); }
            _mode = aes_mode;
            // WinCrypt cannot do CTR mode, we have to do it manually.
            IntPtr buffer = Marshal.AllocCoTaskMem(sizeof(int));
            try {
                int mode = (int)((aes_mode == Mode.Ctr) ? Mode.Ecb : aes_mode);
                Marshal.WriteInt32(buffer, mode);
                bool result = Crypt32.CryptSetKeyParam(_key, 4 /* KP_MODE*/, buffer, 0);
            }
            finally { Marshal.FreeCoTaskMem(buffer); }
        }

        private void destroy()
        {
            Crypt32.CryptDestroyKey(_key);
        }

        internal void Update(byte[] input, byte[] output, bool do_final)
        {
            if (_mode == Mode.Ctr) {
                int index = 0;
                foreach(byte @byte in input) {
                    output[index++] = (byte)(@byte ^ next_keystream_byte());
                }
            }
            else { DoUpdate(input, output, do_final); }
        }

        internal byte[] Update(byte[] input, bool do_final )
        {
            byte[] result = new byte[input.Length];
            Update(input, result, do_final);
            return result;
        }

        internal static byte[] Crypt(Mode aes_mode, KeySize aes_key_size, byte[] key, byte[] input)
        {
            AES aes = CryptoProvider.Instance.CreateAes();
            aes.init(aes_mode, aes_key_size, key);
            return aes.Update(input, (aes_mode == Mode.Ctr || aes_mode == Mode.Ecb) ? false : true);
        }

        private byte next_keystream_byte()
        {
            if (_keystream_pointer >= _key_size) {
                UpdateCounter();
            }
            return _counter_out[_keystream_pointer++];
        }

        private void UpdateCounter()
        {
            EncryptCounter();
            IncrementCounter();
            _keystream_pointer = 0;
        }

        private void EncryptCounter()
        {
            DoUpdate(_counter, _counter_out, false);
        }

        private void IncrementCounter()
        {
            int carry = 1;
            for (int i = (int)_key_size - 1; i >= 0; i--) {
                int x = _counter[i] + carry;
                        carry = (x > 0xff) ? 1 : 0;
                _counter[i] = (byte)x;
            }
        }

        private void DoUpdate(byte[] input, byte[] output, bool do_final)
        {
            Buffer.BlockCopy(input, 0, output, 0, (int)_key_size);
            int crypted_size = (int)_key_size;
            bool result = Crypt32.CryptEncrypt(_key, IntPtr.Zero, do_final,
                0, ref output, ref crypted_size, (int)_key_size);
        }

        // friend class provider;

        private const int CurrentBlobVersion = 2;
        private CryptoProvider _provider;
        private IntPtr /* HCRYPTKEY */ _key;
        private Mode _mode;
        private uint _key_size;

        private byte[] _counter = new byte[32];
        private byte[] _counter_out = new byte[32];
        private int _keystream_pointer;

        internal enum Mode
        {
            Cbc = 1,
            Ecb = 2,
            Ofb = 3,
            Cfb = 4,
            Cts = 5,
            Ctr = 1337,
        };

        internal enum KeySize
        {
            Aes128 = 0x660E,
            Aes192 = 0x660F,
            Aes256 = 0x6610,
        };

        private class BLOBHEADER
        {
            internal void Serialize(IntPtr into, ref int offset)
            {
                Marshal.WriteByte(into + offset, (byte)bType);
                offset += sizeof(byte);
                Marshal.WriteByte(into + offset, bVersion);
                offset += sizeof(byte);
                Marshal.WriteInt16(into + offset, (short)reserved);
                offset += sizeof(ushort);
                Marshal.WriteInt32(into + offset, (int)aiKeyAlg);
                offset += sizeof(uint);
                return;
            }

            internal const int NativeSize = 8;

            internal BlobType bType;
            internal byte bVersion;
            internal ushort reserved;
            internal uint /* ALGID */ aiKeyAlg;
        }

        private class ms_aes_key
        {
            internal IntPtr Serialize(out int size)
            {
                size = BLOBHEADER.NativeSize + sizeof(uint) + KeySize;
                IntPtr result = Marshal.AllocCoTaskMem(size);
                int offset = 0;

                header.Serialize(result, ref offset);
                Marshal.WriteInt32(result, offset, size);
                offset += sizeof(uint);
                Marshal.Copy(key, 0, result + offset, KeySize);
                offset += KeySize;
                return result;
            }

            internal const int KeySize = 32;

            internal BLOBHEADER header; // Must be inlined
            internal uint size;
            internal byte[] key = new byte[KeySize];
        }

        private enum BlobType : byte
        {
            Simple = 1,
            PublicKey = 6,
            PrivateKey = 7,
            PlainText = 8,
            Opaque = 9,
            PublicKeyExtended = 10,
            SymmetricWrapper = 11,
            KeyState = 12
        }
    }
}
