﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TorNet.Cryptography;

namespace TorNet.Tor.Cryptography
{
    internal class KeyAgrement
    {
        public KeyAgrement(int private_key_bytes = Constants.DH_SEC_LEN)
        {
            GenerateKeyPair(private_key_bytes);
        }

        private void GenerateKeyPair(int private_key_bytes)
        {
            Randomizer rnd = CryptoProvider._instance.CreateRandom();

            // generate private key.
            byte[] private_key = new byte[128];
            rnd.get_random_bytes(private_key);
            _private_key = new BigInteger(private_key);

            // generate public key.
            _public_key = KeyAgrement.DH_G.mod_pow(KeyAgrement.DH_P, _private_key);
        }

        internal BigInteger PublicKey
        {
            get { return _public_key; }
        }

        private BigInteger PrivateKey
        {
            get { return _private_key; }
        }

        internal BigInteger GetSharedSecret(BigInteger other_public_key)
        {
            return other_public_key.mod_pow(DH_P, _private_key);
        }

        private BigInteger _public_key;
        private BigInteger _private_key;
        // tor-spec 0.3
        //
        // For Diffie-Hellman, we use a generator (g) of 2.  For the modulus (p), we
        // use the 1024-bit safe prime from rfc2409 section 6.2 whose hex
        // representation is:
        internal static readonly BigInteger DH_P = new BigInteger(new byte[] {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
            0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
            0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
            0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37,
            0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
            0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
            0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6,
            0x49, 0x28, 0x66, 0x51, 0xec, 0xe6, 0x53, 0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, });

        internal static readonly BigInteger DH_G = new BigInteger(new byte[] { 2 });
    }
}
