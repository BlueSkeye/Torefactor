using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TorNet.Interop;

namespace TorNet.Cryptography
{
    internal class RSA
    {
        internal RSA(CryptoProvider crypto_provider)
        {
            _provider = crypto_provider;
        }

        ~RSA()
        {
            Crypt32.CryptDestroyKey(_key);
        }

        internal void set_public_key(byte[] public_key)
        {
            SetKey(public_key, Crypt32.RSA_CSP_PUBLICKEYBLOB);
        }

        internal void set_private_key(byte[] private_key)
        {
            SetKey(private_key, Crypt32.PKCS_RSA_PRIVATE_KEY);
        }

        private void SetKey(byte[] keyData, string keyType)
        {
            int key_blob_size = 0;
            _key_blob = null;
            bool result = Crypt32.CryptDecodeObject(Crypt32.X509_ASN_ENCODING, keyType,
                keyData, keyData.Length, 0, ref _key_blob, ref key_blob_size);
            _key_blob = new byte[key_blob_size];
            result = Crypt32.CryptDecodeObject(Crypt32.X509_ASN_ENCODING, keyType,
                keyData, keyData.Length, 0, ref _key_blob, ref key_blob_size);
            import_key(_key_blob);
        }

        internal byte[] public_encrypt(byte[] input, bool do_final)
        {
            byte[] output = new byte[_key_size];
            Buffer.BlockCopy(input, 0, output, 0, input.Length);
            int dword_input_size = input.Length;
            bool result = Crypt32.CryptEncrypt(_key, IntPtr.Zero, do_final,
                Crypt32.CRYPT_OAEP, ref output, ref dword_input_size, _key_size);
            for (int i = 0; i < (_key_size / 2); i++) {
                byte c = output[i];
                output[i] = output[_key_size - 1 - i];
                output[_key_size - 1 - i] = c;
            }
            Helpers.Resize(ref output, dword_input_size); // is this necessary?
            return output;
        }

        internal byte[] private_decrypt(byte[] input, bool do_final)
        {
            byte[] output = new byte[_key_size];
            Buffer.BlockCopy(input, 0, output, 0, input.Length);
            for (int i = 0; i < (_key_size / 2); i++) {
                byte c = output[i];
                output[i] = output[_key_size - 1 - i];
                output[_key_size - 1 - i] = c;
            }
            int dword_input_size = input.Length;
            bool result = Crypt32.CryptDecrypt(_key, IntPtr.Zero, do_final, Crypt32.CRYPT_OAEP,
                ref output, ref dword_input_size);
            Helpers.Resize(ref output, dword_input_size); // is this necessary?
            return output;
        }

        internal void import_key(byte[] key_blob)
        {
            bool result = Crypt32.CryptImportKey(_provider.Handle, key_blob,
                key_blob.Length, IntPtr.Zero, 0, out _key);
            int param_size = sizeof(uint);
            byte[] rawData = new byte[sizeof(int)];
            Crypt32.CryptGetKeyParam(_key, Crypt32.KP_KEYLEN, ref rawData, ref param_size, 0);
            _key_size = (((((rawData[3] * 256) + rawData[2]) * 256) + rawData[1]) + 256) + rawData[0];
            _key_size /= 8;
        }

        internal static byte[] public_encrypt(byte[] input, byte[] public_key)
        {
            RSA rsa = CryptoProvider.Instance.CreateRSA();
            rsa.set_public_key(public_key);
            return rsa.public_encrypt(input, true);
        }

        internal static byte[] private_decrypt(byte[] input, byte[] private_key)
        {
            RSA rsa = CryptoProvider.Instance.CreateRSA();
            rsa.set_private_key(private_key);
            return rsa.private_decrypt(input, true);
        }

        private CryptoProvider _provider;
        private IntPtr /* HCRYPTKEY */ _key;
        private int _key_size;
        private byte[] _key_blob;
    }
}
