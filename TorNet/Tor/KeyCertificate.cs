using System;
using System.Net;
using System.Runtime.InteropServices;

using TorNet.Cryptography;
using TorNet.Interop;

namespace TorNet.Tor
{
    internal class KeyCertificate
    {
        internal byte[] CrossSignature { get; set; }
        internal IPEndPoint EndPoint { get; set; }
        internal DateTime Expires { get; set; }
        internal byte[] Fingerprint { get; set; }
        internal byte[] IdentityKey { get; set; }
        internal DateTime Published { get; set; }
        internal byte[] Signature { get; set; }
        internal byte[] SigningKey { get; set; }
        internal byte[] ToBeHashed { get; set; }

        /// <summary>Verify the certificate content according to rules defined
        /// at 3.1 in dir-spec.txt</summary>
        internal void Verify(Authority certificateOwner)
        {
            if (null == certificateOwner) { throw new ArgumentNullException(); }
            // Verify the CrossSignature.
            // 1) Get IdentityKey digest.
            byte[] identityKeyDigest = SHA1.Hash(IdentityKey);

            // 2) Make sure it matches the declared owner.
            // was implemented as router_digest_is_trusted_dir(identityKeyDigest);
            // TODO : This will fail on an identity key update.
            byte[] certificateOwnerIdentityKeyDigest =
                SHA1.Hash(certificateOwner.Identity.DecodeHexadecimalEncodedString());
            if (!Helpers.AreEquals(identityKeyDigest, certificateOwnerIdentityKeyDigest)) {
                throw new TorSecurityException();
            }

            // 2) Compute digest of ToBeHashed
            IntPtr hHasher = IntPtr.Zero;
            IntPtr nativeSignature = IntPtr.Zero;
            IntPtr hPublicSigningKey = IntPtr.Zero;
            try {
                SHA1.Hash(ToBeHashed, out hHasher);
                Marshal.AllocCoTaskMem(Signature.Length);
                Marshal.Copy(Signature, 0, nativeSignature, Signature.Length);
                hPublicSigningKey =  CryptoProvider.ImportRsaPublicKey(SigningKey);
                if (!Advapi32.CryptVerifySignature(hHasher, nativeSignature, Signature.Length,
                    hPublicSigningKey, IntPtr.Zero, Advapi32.SignatureVerificationFlags.NoHashOID))
                {
                    throw new CryptographyException((WinErrors)(uint)Marshal.GetLastWin32Error());
                }
            }
            finally {
                if(IntPtr.Zero != hPublicSigningKey) {
                    Advapi32.CryptDestroyKey(hPublicSigningKey);
                }
                if (IntPtr.Zero != nativeSignature) {
                    Marshal.FreeCoTaskMem(nativeSignature);
                }
                if (IntPtr.Zero != hHasher) {
                    Advapi32.CryptDestroyHash(hHasher);
                }
            }
            // Remind : HashValue = SHA1.Hash(base._toBeHashed);
            //byte[] signed_digest = crypto_pk_public_checksig(IdentityKey, tok->object_body, tok->object_size)

            // crypto_pk_public_checksig main action is : 
            //RSA_public_decrypt((int)fromlen,
            //            (unsigned char *)from, (unsigned char*)to,
            //            env->key, RSA_PKCS1_PADDING);

            //byte[] signed_digest = RSA_public_decrypt((int)fromlen,
            //    (byte[])from, (byte[])to,
            //    env->key, RSA_PKCS1_PADDING);
            //// tor_memneq(identityKeyDigest, signed_digest);
            //if (!Helpers.AreEquals(identityKeyDigest, signedDigest)) {
            //    throw new TorSecurityException();
            //}
        }
    }
}
