using System;

namespace TorNet.Tor
{
    internal static class WellKnownUrlRetriever
    {
        internal static string GetMostRecentServerDescriptorPath(string identityFingerprint,
            bool compressed)
        {
            return string.Format(MostRecentServerDescriptorByFingerprint, identityFingerprint)
                + ((compressed) ? CompressionSuffix : string.Empty);
        }

        private static string GetRelativePath(Document document, bool compresssed)
        {
            switch(document) {
                case Document.Undefined:
                    throw new ArgumentException();
                case Document.MostRecentV3Consensus:
                    return MostRecentV3ConsensusUrlPath +
                        ((compresssed) ? CompressionSuffix : string.Empty);
                default:
                    Helpers.WTF();
                    return null; // Unreachable.
            }
        }

        internal static string Retrieve(Document document, Authority from = null,
            bool compressed = true)
        {
            if (null == from) {
                from = Authority.GetRandomAuthority();
            }
            return Authority.DownloadFromRandomAuthority(
                GetRelativePath(document, compressed), compressed);
        }

        internal const string CompressionSuffix = ".z";
        private const string MostRecentServerDescriptorByFingerprint = "/tor/server/fp/{0}";
        internal const string MostRecentV3ConsensusUrlPath = "/tor/status-vote/current/consensus";

        internal enum Document
        {
            Undefined,
            MostRecentV3Consensus,
        }
    }
}
