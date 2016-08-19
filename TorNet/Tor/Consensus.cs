#define PROXIED

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

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

        /// <summary>Retrieve a fully qualified path for storage of the cached
        /// consensus.</summary>
        private static string CachedConsensusFilePath
        {
            get {
                if (null == _cachedConsensusFilePath) {
                    _cachedConsensusFilePath =
                        Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                            CachedConsensusFileName);
                }
                return _cachedConsensusFilePath;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) { GC.SuppressFinalize(this); }
            destroy();
        }

        /// <summary>Retrieve and parse a valid consensus, depending on flags value,
        /// either grab it from cache and/or download it from a random authority.</summary>
        /// <param name="options"></param>
        internal static Consensus Fetch(Options options)
        {
            string consensusContent = null;
            if (   (0 == (options & Options.ForceDownload))
                && (0 != (options & Options.UseCache))
                && File.Exists(CachedConsensusFilePath))
            {
                consensusContent = File.ReadAllText(CachedConsensusFilePath);
            }
            else if (   (0 != (options & Options.ForceDownload))
                     || (0 != (options & Options.DoNotUseCache)))
            {
                consensusContent = WellKnownUrlRetriever.Retrieve(
                    WellKnownUrlRetriever.Document.MostRecentV3Consensus);
                if (0 == (options & Options.DoNotUseCache)) {
                    File.WriteAllText(CachedConsensusFilePath, consensusContent);
                }
            }
            Consensus result = null;
            if (null != consensusContent) {
                result = Parser.ParseAndValidate(consensusContent);
            }
            // if the consensus is invalid, we have to download it anyway
            // TODO : Don't download if options do not allow to do so.
            if ((null == result) || (result.ValidUntilUTC < DateTime.UtcNow)) {
                consensusContent = WellKnownUrlRetriever.Retrieve(
                    WellKnownUrlRetriever.Document.MostRecentV3Consensus);
                if (0 == (options & Options.DoNotUseCache)) {
                    File.WriteAllText(CachedConsensusFilePath, consensusContent);
                }
                result = Parser.ParseAndValidate(consensusContent);
            }
            return result;
        }

        private void destroy()
        {
            foreach(OnionRouter router in _onionRouterMap.Values) {
                router.Dispose();
            }
        }

        internal OnionRouter get_random_onion_router_by_criteria(SearchCriteria criteria)
        {
            foreach(KeyValuePair<string, OnionRouter> pair in _onionRouterMap) {
                OnionRouter router = pair.Value;
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
                return router;
            }
            return null;
        }

        internal OnionRouter get_onion_router_by_name(string name)
        {
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
        private static string _cachedConsensusFilePath;

        [Flags()]
        internal enum Options
        {
            None = 0,
            UseCache = 0x01,
            DoNotUseCache = 0x02,
            ForceDownload = 0x04,
        }
    }
}
