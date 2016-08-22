using System;

namespace TorNet.Tor
{
    internal class SignatureDescriptor
    {
        internal SignatureDescriptor(Authority signer, byte[] toBeSigned, byte[] signature)
        {
            if (null == signer) { throw new ArgumentNullException(); }
            if (null == toBeSigned) { throw new ArgumentNullException(); }
            if (null == signature) { throw new ArgumentNullException(); }
            Signer = signer;
            _toBeSigned = (byte[])toBeSigned.Clone();
            _signature = (byte[])signature.Clone();
            return;
        }

        internal Authority Signer { get; private set; }

        internal bool Validate(ValidationPolicy policy)
        {
            bool valid = false;

            // Retrieve the signing key having the given digest and originating
            // from the given authority. Retrieval may occur from another authority
            // than the one owning the signing key.
            if (!valid && (ValidationPolicy.AllSignaturesMustMatch == policy)) {
                throw new TorSecurityException();
            }
            return valid;
        }

        private byte[] _signature;
        private byte[] _toBeSigned;

        internal enum ValidationPolicy
        {
            Undefined,
            AllSignaturesMustMatch,
            AtLeastOneSignaturePerSignerMustMatch,
            AtLeastOneSignatureMustMatch,
            DontCare
        }
    }
}
