using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TorNet.Cryptography;

namespace TorNet.Tor.Cryptography
{
    internal class HybridEncryptor
    {
        private const int PK_ENC_LEN = 128;
        private const int PK_PAD_LEN = 42;
        private const int PK_DATA_LEN = PK_ENC_LEN - PK_PAD_LEN;
        private const int KEY_LEN = 16;
        private const int PK_DATA_LEN_WITH_KEY = PK_DATA_LEN - KEY_LEN;

        // Encrypt the entire contents of the byte array "data" with the given "TorPublicKey"
        // according to the "hybrid encryption" scheme described in the main Tor specification(tor-spec.txt).
        internal static byte[] Encrypt(byte[] data, byte[] public_key)
        {
            if (data.Length < PK_DATA_LEN) {
                return RSA.public_encrypt(data, public_key);
            }
            byte[] random_key = CryptoProvider.Instance.CreateRandom().get_random_bytes(KEY_LEN);

            // RSA( K | M1 ) --> C1
            List<byte> k_and_m1 = new List<byte>();
            k_and_m1.AddRange(random_key);
            k_and_m1.AddRange(data.Slice(0, PK_DATA_LEN_WITH_KEY));
            byte[] c1 = RSA.public_encrypt(k_and_m1.ToArray(), public_key);

            // AES_CTR(M2)  --> C2
            byte[] m2 = data.Slice(PK_DATA_LEN_WITH_KEY);
            byte[] c2 = AES.Crypt(AES.Mode.Ctr, AES.KeySize.Aes128, random_key, m2);

            // C1 | C2
            byte[] result = new byte[c1.Length+ c2.Length];
            Buffer.BlockCopy(c1, 0, result, 0, c1.Length);
            Buffer.BlockCopy(c2, 0, result, c1.Length, c2.Length);
            return result;
        }
    }
}
