﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace TorNet.Tor
{
    internal partial class Consensus : IDisposable
    {
        internal Consensus(Options options = Options.use_cache)
        {
            fetch_consensus(options);
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
            destroy();
        }

        internal void fetch_consensus(Options options)
        {
            string consensus_content = null;
            if (   (0 == (options & Options.force_download))
                && (0 != (options & Options.use_cache))
                && File.Exists(cached_consensus_filename))
            {
                consensus_content = File.ReadAllText(cached_consensus_filename);
            }
            else if (   (0 != (options & Options.force_download))
                     || (0 != (options & Options.do_not_use_cache)))
            {
                consensus_content = download_from_random_authority("/tor/status-vote/current/consensus");
                if (0 == (options & Options.do_not_use_cache)) {
                    File.WriteAllText(cached_consensus_filename, consensus_content);
                }
            }
            if (null != consensus_content) {
                parse_consensus(consensus_content);
            }
            // if the consensus is invalid, we have to download it anyway
            if (_valid_until < DateTime.Now) {
                consensus_content = download_from_random_authority("/tor/status-vote/current/consensus");
                if (0 == (options & Options.do_not_use_cache)) {
                    File.WriteAllText(cached_consensus_filename, consensus_content);
                }
                parse_consensus(consensus_content);
            }
        }

        private void destroy()
        {
            foreach(OnionRouter router in _onion_router_map.Values) {
                router.Dispose();
            }
        }

        internal string get_router_consensus(string identity_fingerprint)
        {
            Globals.LogInfo("consensus::get_router_consensus() [identity_fingerprint: {0}]",
                identity_fingerprint);
            return download_from_random_authority("/tor/server/fp/" + identity_fingerprint);
        }

        internal OnionRouter get_random_onion_router_by_criteria(SearchCriteria criteria)
        {
            foreach(KeyValuePair<string, OnionRouter> pair in _onion_router_map) {
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
            foreach(OnionRouter router in _onion_router_map.Values) {
                if (name == router.Name) {
                    return router;
                }
            }
            return null;
        }

        internal OnionRouter get_onion_router_by_identity_fingerprint(string identity_fingerprint)
        {
            return _onion_router_map[identity_fingerprint];
        }

        internal List<OnionRouter> get_onion_routers_by_criteria(SearchCriteria criteria)
        {
            List<OnionRouter> result = new List<OnionRouter>();
            foreach (OnionRouter router in _onion_router_map.Values) {
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

        private string download_from_random_authority(string path)
        {
            // TODO: chose really random authority.
            Globals.LogInfo("consensus::download_from_random_authority() [path: {0}]", path);
            string authority_line = authorities[3];
            string[] splitted = authority_line.Split(' ');
            string[] ip_port = splitted[3].Split(':');
            string consensus_content =
                Helpers.HttpGet(ip_port[0], (ushort)int.Parse(ip_port[1]), path).Result;
                //net::http::client::get(ip_port[0], (ushort)int.Parse(ip_port[1]),
                //path);
            return consensus_content;
        }

        private void parse_consensus(string consensus_content)
        {
            new Parser().Parse(this, consensus_content);
        }

        private static readonly string[] authorities = new string[] {
              "moria1 orport=9101 v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",
              "tor26 orport=443 v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
              "dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
              "Tonga orport=443 bridge 82.94.251.203:80 4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D",
              "turtles orport=9090 v3ident=27B6B5996C426270A5C95488AA5BCEB6BCC86956 76.73.17.194:9030 F397 038A DC51 3361 35E7 B80B D99C A384 4360 292B",
              "gabelmoo orport=443 v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 212.112.245.170:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
              "dannenberg orport=443 v3ident=585769C78764D58426B8B52B6651A5A71137189A 193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
              "urras orport=80 v3ident=80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34:443 0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417",
              "maatuska orport=80 v3ident=49015F787433103580E3B66A1707A00E60F2D15B 171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
              "Faravahar orport=443 v3ident=EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 154.35.32.5:80 CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC"
        };

        private const string cached_consensus_filename = "cached-consensus";
        private Dictionary<string, OnionRouter> _onion_router_map = new Dictionary<string, OnionRouter>();
        private DateTime _valid_until;

        [Flags()]
        internal enum Options
        {
            None = 0,
            use_cache         = 0x01,
            do_not_use_cache  = 0x02,
            force_download    = 0x04,
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