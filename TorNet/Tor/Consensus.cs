using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Net.Http;
using System.Threading.Tasks;

namespace TorNet.Tor
{
    internal partial class Consensus : IDisposable
    {
        internal Consensus(Options options = Options.UseCache)
        {
            FetchConsensus(options);
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

        /// <summary>Randomly select an authority in the hardccoded list and
        /// download current consensus from a well known path.</summary>
        /// <param name="path"></param>
        /// <returns></returns>
        private string DownloadFromRandomAuthority(string path)
        {
            Globals.LogInfo("consensus::download_from_random_authority() [path: {0}]", path);
            int authorityIndex;
            using (RandomNumberGenerator randomizer = RandomNumberGenerator.Create()) {
                byte[] buffer = new byte[sizeof(ulong)];
                randomizer.GetBytes(buffer);
                authorityIndex = (int)(buffer.ToUInt64() % (ulong)authorities.Length);
            }
            string authorityLine = authorities[authorityIndex];
            string[] splitted = authorityLine.Split(' ');
            string[] addressAndPort = splitted[3].Split(':');

            string result = Helpers.HttpGet(addressAndPort[0], (ushort)int.Parse(addressAndPort[1]), path).Result;
            return result;
        }

        internal void FetchConsensus(Options options)
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
                consensusContent = DownloadFromRandomAuthority("/tor/status-vote/current/consensus");
                if (0 == (options & Options.DoNotUseCache)) {
                    File.WriteAllText(CachedConsensusFilePath, consensusContent);
                }
            }
            if (null != consensusContent) {
                ParseConsensus(consensusContent);
            }
            // if the consensus is invalid, we have to download it anyway
            if (_validUntil < DateTime.Now) {
                consensusContent = DownloadFromRandomAuthority("/tor/status-vote/current/consensus");
                if (0 == (options & Options.DoNotUseCache)) {
                    File.WriteAllText(CachedConsensusFileName, consensusContent);
                }
                ParseConsensus(consensusContent);
            }
        }

        private void destroy()
        {
            foreach(OnionRouter router in _onionRouterMap.Values) {
                router.Dispose();
            }
        }

        internal string get_router_consensus(string identity_fingerprint)
        {
            Globals.LogInfo("consensus::get_router_consensus() [identity_fingerprint: {0}]",
                identity_fingerprint);
            return DownloadFromRandomAuthority("/tor/server/fp/" + identity_fingerprint);
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
                if (criteria.flags != OnionRouter.status_flags.none) {
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

        internal OnionRouter get_onion_router_by_identity_fingerprint(string identity_fingerprint)
        {
            return _onionRouterMap[identity_fingerprint];
        }

        internal List<OnionRouter> get_onion_routers_by_criteria(SearchCriteria criteria)
        {
            List<OnionRouter> result = new List<OnionRouter>();
            foreach (OnionRouter router in _onionRouterMap.Values) {
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
                if (criteria.flags != OnionRouter.status_flags.none) {
                    if ((router.Flags & criteria.flags) != criteria.flags) {
                        continue;
                    }
                }
                result.Add(router);
            }
            return result;
        }

        private void ParseConsensus(string consensus_content)
        {
            new Parser().Parse(this, consensus_content);
        }

        /// <summary>Hardcoded list of authorities.
        /// TODO : These long strings are easily spottable by various firewalls and
        /// filtering proxies. Some kind of encoding should be applied here.</summary>
        /// <remarks>Responsivness is as of our testing (summer 2016)</remarks>
        private static readonly string[] authorities = new string[] {
            /* responsive */ "moria1 orport=9101 v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",
            /* responsive */ "tor26 orport=443 v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
            /* responsive */ "dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
            "Tonga orport=443 bridge 82.94.251.203:80 4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D",
            /* unresponsive */ // "turtles orport=9090 v3ident=27B6B5996C426270A5C95488AA5BCEB6BCC86956 76.73.17.194:9030 F397 038A DC51 3361 35E7 B80B D99C A384 4360 292B",
            /* unresponsive */ // "gabelmoo orport=443 v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 212.112.245.170:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
            /* responsive */ "dannenberg orport=443 v3ident=585769C78764D58426B8B52B6651A5A71137189A 193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
            // Removed as per Tor 0.2.8.6
            // "urras orport=80 v3ident=80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34:443 0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417",
            /* responsive */ "maatuska orport=80 v3ident=49015F787433103580E3B66A1707A00E60F2D15B 171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
            "Faravahar orport=443 v3ident=EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 154.35.32.5:80 CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC"
        };

        private const string CachedConsensusFileName = "cached-consensus";
        private static string _cachedConsensusFilePath;
        private Dictionary<string, OnionRouter> _onionRouterMap = new Dictionary<string, OnionRouter>();
        private DateTime _validUntil;

        [Flags()]
        internal enum Options
        {
            None = 0,
            UseCache = 0x01,
            DoNotUseCache = 0x02,
            ForceDownload = 0x04,
        }

        public class SearchCriteria
        {
            internal List<ushort> allowed_dir_ports = new List<ushort>();
            internal List<ushort> allowed_or_ports = new List<ushort>();
            internal List<OnionRouter> forbidden_onion_routers = new List<OnionRouter>();
            internal OnionRouter.status_flags flags;
        }
    }
}
