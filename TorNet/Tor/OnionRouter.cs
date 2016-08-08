using System;
using System.Collections.Generic;
using System.Net;

using TorNet.Tor.Parsers;

namespace TorNet.Tor
{
    internal class OnionRouter : IDisposable
    {
        internal OnionRouter(ConsensusOrVote consensus, string name, string identityFingerprint,
            string digest, DateTime publishedAt, IPAddress ipAddress, ushort orPort, ushort dirPort,
            byte[] onion_key = null, byte[] signing_key = null, byte[] service_key = null)
        {
            if (string.IsNullOrEmpty(identityFingerprint)) {
                throw new ArgumentNullException();
            }
            Owner = consensus;
            Name = name;
            IPAddress = ipAddress;
            ORPort = orPort;
            DirPort = dirPort;
            IdentityFingerprint = identityFingerprint;
            Flags = 0;
            _onion_key = onion_key;
            _signing_key = signing_key;
            _service_key = service_key;
            return;
        }

        internal ushort DirPort { get; set; }

        internal int EstimatedBandwidth { get; set; }

        internal StatusFlags Flags { get; set; }

        internal string IdentityFingerprint { get; set; }

        internal IPAddress IPAddress { get; set; }

        internal IPEndPoint IPV6EndPoint { get; set; }

        internal int MeasuredBandwidth { get; set; }

        internal string Name { get; set; }

        internal byte[] OnionKey
        {
            get {
                if (Helpers.IsNullOrEmpty(_onion_key)) { FetchDescriptor(); }
                return _onion_key;
            }
            set { _onion_key = value; }
        }

        internal ushort ORPort { get; set; }

        internal ConsensusOrVote Owner { get; private set; }

        internal DateTime PublishedUTC { get; set; }

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

        internal bool Unmeasured { get; set; }

        internal string Version { get; set; }

        internal void Accept(ushort port)
        {
            _acceptedRanges.Add(new AddressRange(port, port));
        }

        internal void Accept(ushort from, ushort to)
        {
            _acceptedRanges.Add(new AddressRange(from, to));
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
            ServerDescriptorParser.Parse(this, _consensus.get_router_consensus(IdentityFingerprint));
        }

        internal void Reject(ushort port)
        {
            _rejectedRanges.Add(new AddressRange(port, port));
        }

        internal void Reject(ushort from, ushort to)
        {
            _rejectedRanges.Add(new AddressRange(from, to));
        }

        private List<AddressRange> _acceptedRanges = new List<AddressRange>();
        private Consensus _consensus;
        private byte[] _onion_key;
        private List<AddressRange> _rejectedRanges = new List<AddressRange>();
        private byte[] _signing_key;
        private byte[] _service_key; // for introduction point

        internal struct AddressRange
        {
            internal AddressRange(ushort from, ushort to)
            {
                this.from = from;
                this.to = to;
            }

            internal ushort from;
            internal ushort to;
        }

        [Flags]
        internal enum StatusFlags : ushort
        {
            none = 0x0000,
            // if the router is a directory authority
            Authority = 0x0001,
            // if the router is believed to be useless as an exit node
            // (because its ISP censors it, because it is behind a restrictive
            // proxy, or for some similar reason)
            BadExit = 0x0002,
            // if the router is more useful for building
            // general - purpose exit circuits than for relay circuits.The
            // path building algorithm uses this flag; see path - spec.txt.
            Exit = 0x0004,
            // if the router is suitable for high - bandwidth circuits
            Fast = 0x0008,
            // if the router is suitable for use as an entry guard
            Guard = 0x0010,
            // if the router is considered a v2 hidden service directory
            HSDir = 0x0020,
            // if the router's identity-nickname mapping is canonical,
            // and this authority binds names
            Named = 0x0040,
            // if any Ed25519 key in the router's descriptor or
            // microdesriptor does not reflect authority consensus
            NoEd25519Consensus = 0x0080,
            // if the router is suitable for long - lived circuits
            Stable = 0x0100,
            // if the router is currently usable
            Running = 0x0200,
            // if another router has bound the name used by this
            // router, and this authority binds names
            Unnamed = 0x0400,
            // if the router has been 'validated'
            Valid = 0x0800,
            // if the router implements the v2 directory protocol or
            // higher
            V2Dir = 0x1000,
        }
    }
}
