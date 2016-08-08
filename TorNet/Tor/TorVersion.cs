using System;

namespace TorNet.Tor
{
    internal class TorVersion
    {
        internal TorVersion(Version version, string qualifier)
        {
            Version = version;
            Qualifier = qualifier;
        }

        internal string Qualifier { get; private set; }
        internal Version Version { get; private set; }
    }
}
