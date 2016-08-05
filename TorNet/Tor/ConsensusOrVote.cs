using System;

namespace TorNet.Tor
{
    internal abstract class ConsensusOrVote
    {
        internal DateTime ValidAfter { get; set; }
    }
}
