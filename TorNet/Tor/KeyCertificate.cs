using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace TorNet.Tor
{
    internal class KeyCertificate
    {
        internal byte[] CrossSignature { get; set; }
        internal IPEndPoint EndPoint { get; set; }
        internal DateTime Expires { get; set; }
        internal byte[] Fingerprint { get; set; }
        internal DateTime Published { get; set; }
        internal byte[] SigningKey { get; set; }
    }
}
