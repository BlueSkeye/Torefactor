using System;
using System.Collections.Generic;
using System.Net;

using TorNet.Tor.Parsers;

namespace TorNet.Tor
{
    internal class OnionRouter : IDisposable
    {
        internal OnionRouter(Consensus consensus, string name, string ip, ushort or_port,
            ushort dir_port, string identity_fingerprint, byte[] onion_key = null,
            byte[] signing_key = null, byte[] service_key = null)
        {
            _consensus = consensus;
            _name = name;
            _ip = IPAddress.Parse(ip);
            _or_port = or_port;
            _dir_port = dir_port;
            _identity_fingerprint = identity_fingerprint;
            _flags = 0;
            _onion_key = onion_key;
            _signing_key = signing_key;
            _service_key = service_key;
        }

        internal Consensus Consensus
        {
            get { return _consensus; }
        }

        internal string Name
        {
            get { return _name; }
            set { _name = value; }
        }

        internal IPAddress IPAddress
        {
            get { return _ip; }
            set { _ip = value; }
        }

        internal ushort DirPort
        {
            get { return _dir_port; }
            set { _dir_port = value; }
        }

        internal ushort ORPort
        {
            get { return _or_port; }
            set { _or_port = value; }
        }

        internal string IdentityFingerprint
        {
            get { return _identity_fingerprint; }
            set { _identity_fingerprint = value; }
        }

        internal status_flags Flags
        {
            get { return _flags; }
            set { _flags = value; }
        }

        internal byte[] OnionKey
        {
            get
            {
                if (Helpers.IsNullOrEmpty(_onion_key)) { FetchDescriptor(); }
                return _onion_key;
            }
            set { _onion_key = value; }
        }

        internal byte[] ServiceKey
        {
            get { return _service_key; }
            set { _service_key = value; }
        }

        internal byte[] SigningKey
        {
            get
            {
                if (Helpers.IsNullOrEmpty(_signing_key)) { FetchDescriptor(); }
                return _signing_key;
            }
            set { _signing_key = value; }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) { GC.SuppressFinalize(this); }
            return;
        }

        private void FetchDescriptor()
        {
            ServerDescriptorParser.Parse(this, _consensus.get_router_consensus(_identity_fingerprint));
        }

        private Consensus _consensus;
        private string _name;
        private IPAddress _ip;
        private ushort _or_port;
        private ushort _dir_port;
        private string _identity_fingerprint;
        private status_flags _flags;
        private byte[] _onion_key;
        private byte[] _signing_key;
        private byte[] _service_key; // for introduction point

        [Flags]
        internal enum status_flags : ushort
        {
            none = 0x0000,
            // if the router is a directory authority
            authority = 0x0001,
            // if the router is believed to be useless as an exit node
            // (because its ISP censors it, because it is behind a restrictive
            // proxy, or for some similar reason)
            bad_exit = 0x0002,
            // if the router is more useful for building
            // general - purpose exit circuits than for relay circuits.The
            // path building algorithm uses this flag; see path - spec.txt.
            exit = 0x0004,
            // if the router is suitable for high - bandwidth circuits
            fast = 0x0008,
            // if the router is suitable for use as an entry guard
            guard = 0x0010,
            // if the router is considered a v2 hidden service directory
            hsdir = 0x0020,
            // if the router's identity-nickname mapping is canonical,
            // and this authority binds names
            named = 0x0040,
            // if any Ed25519 key in the router's descriptor or
            // microdesriptor does not reflect authority consensus
            no_ed_consensus = 0x0080,
            // if the router is suitable for long - lived circuits
            stable = 0x0100,
            // if the router is currently usable
            running = 0x0200,
            // if another router has bound the name used by this
            // router, and this authority binds names
            unnamed = 0x0400,
            // if the router has been 'validated'
            valid = 0x0800,
            // if the router implements the v2 directory protocol or
            // higher
            v2dir = 0x1000,
        }
    }
}
