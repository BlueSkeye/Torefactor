using System;

namespace TorNet.Interop
{
    [Flags()]
    internal enum CertificateEncodingType : int
    {
        X509Asn = 0x00000001,
        PKCSAsn = 0x00010000,
    }
}
