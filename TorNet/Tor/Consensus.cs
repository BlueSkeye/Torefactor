#define PROXIED

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TorNet.Tor
{
    internal partial class Consensus : ConsensusOrVote, IDisposable
    {
        private Consensus()
        {
            return;
        }

        ~Consensus()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) { GC.SuppressFinalize(this); }
            Destroy();
        }

        /// <summary>Retrieve and parse a valid consensus, depending on flags value,
        /// either grab it from cache and/or download it from a random authority.</summary>
        /// <param name="options"></param>
        internal static Consensus Fetch(RetrievalOptions options)
        {
            // TODO : Factorize RetrievalOptions behavior with Authority.GetKeyCertificate
            string consensusContent = null;
            if (   (0 == (RetrievalOptions.ForceDownload & options))
                && (0 != (RetrievalOptions.UseCache & options))
                && File.Exists(CacheManager.CachedConsensusFilePath))
            {
                consensusContent = File.ReadAllText(CacheManager.CachedConsensusFilePath);
            }
            else if (   (0 != (options & RetrievalOptions.ForceDownload))
                     || (0 != (options & RetrievalOptions.DoNotUseCache)))
            {
                consensusContent = Encoding.ASCII.GetString(
                    WellKnownUrlRetriever.Retrieve(
                        WellKnownUrlRetriever.Document.MostRecentV3Consensus));
                if (0 == (RetrievalOptions.DoNotUseCache & options)) {
                    File.WriteAllText(CacheManager.CachedConsensusFilePath, consensusContent);
                }
            }
            Consensus result = null;
            if (null != consensusContent) {
                result = Parser.ParseAndValidate(consensusContent);
            }
            // if the consensus is invalid, we have to download it anyway
            // TODO : Don't download if options do not allow to do so.
            if ((null == result) || (result.ValidUntilUTC < DateTime.UtcNow)) {
                consensusContent = Encoding.ASCII.GetString(
                    WellKnownUrlRetriever.Retrieve(
                        WellKnownUrlRetriever.Document.MostRecentV3Consensus));
                if (0 == (options & RetrievalOptions.DoNotUseCache)) {
                    File.WriteAllText(CacheManager.CachedConsensusFilePath, consensusContent);
                }
                result = Parser.ParseAndValidate(consensusContent);
            }
            return result;
        }

        private void Destroy()
        {
            foreach(OnionRouter router in _onionRouterMap.Values) {
                router.Dispose();
            }
        }

        internal OnionRouter GetRandomRouter(SearchCriteria criteria = null)
        {
            List<OnionRouter> candidates = new List<OnionRouter>();
            foreach(KeyValuePair<string, OnionRouter> pair in _onionRouterMap) {
                OnionRouter router = pair.Value;
                if (null != criteria) {
                    if (!Helpers.IsNullOrEmpty(criteria.allowed_dir_ports)) {
                        if (-1 == criteria.allowed_dir_ports.IndexOf(router.DirPort)) {
                            continue;
                        }
                    }
                    if (!Helpers.IsNullOrEmpty(criteria.allowed_or_ports)) {
                        if (-1 == criteria.allowed_or_ports.IndexOf(router.ORPort)) {
                            continue;
                        }
                    }
                    if (!Helpers.IsNullOrEmpty(criteria.forbidden_onion_routers)) {
                        if (-1 == criteria.forbidden_onion_routers.IndexOf(router)) {
                            continue;
                        }
                    }
                    if (criteria.flags != OnionRouter.StatusFlags.none) {
                        if ((router.Flags & criteria.flags) != criteria.flags) {
                            continue;
                        }
                    }
                }
                candidates.Add(router);
            }
            if (0 == candidates.Count) { return null; }
            OnionRouter nextHop = candidates.GetRandom();
            return null;
        }

        internal OnionRouter GetRouter(string name)
        {
            if (string.IsNullOrEmpty(name)) { throw new ArgumentNullException(); }
            foreach(OnionRouter router in _onionRouterMap.Values) {
                if (name == router.Name) {
                    return router;
                }
            }
            return null;
        }

        private void ParseConsensus(string candidateContent)
        {
            Parser.ParseAndValidate(candidateContent);
        }

        private const string CachedConsensusFileName = "cached-consensus";
    }
}
