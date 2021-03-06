﻿using System;
using System.Collections.Generic;
using System.Text;

namespace TorNet.Tor
{
    internal abstract class ConsensusOrVote
    {
        internal TorVersion[] ClientVersions { get; set; }
        internal int DistSeconds { get; set; }
        internal DateTime FreshUntilUTC { get; set; }
        internal string[] KnownFlags { get; set; }
        internal KeyValuePair<string, int>[] Parameters { get; set; }
        internal TorVersion[] ServerVersions { get; set; }
        internal DateTime ValidAfterUTC { get; set; }
        internal DateTime ValidUntilUTC { get; set; }
        internal int VoteSeconds { get; set; }

        internal void AddAuthority(Authority candidate)
        {
            _authorities.Add(candidate);
            return;
        }

        internal void AddSignatureDescriptor(SignatureDescriptor descriptor)
        {
            if (null == descriptor) { throw new ArgumentNullException(); }
            if (!_authorities.Contains(descriptor.Signer)) {
                throw new InvalidOperationException();
            }
            _signatureDescriptors.Add(descriptor);
            return;
        }

        internal IEnumerable<SignatureDescriptor> EnumerateSignatureDescriptors()
        {
            foreach(SignatureDescriptor item in _signatureDescriptors) {
                yield return item;
            }
            yield break;
        }

        internal Authority GetAuthority(string identity)
        {
            foreach(Authority candidate in _authorities) {
                if (candidate.Identity == identity) { return candidate; }
            }
            return null;
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
                if (criteria.flags != OnionRouter.StatusFlags.none) {
                    if ((router.Flags & criteria.flags) != criteria.flags) {
                        continue;
                    }
                }
                result.Add(router);
            }
            return result;
        }

        internal OnionRouter get_onion_router_by_identity_fingerprint(string identity_fingerprint)
        {
            return _onionRouterMap[identity_fingerprint];
        }

        internal string get_router_consensus(string identityFingerprint, bool compressed = true)
        {
            Globals.LogInfo("consensus::get_router_consensus() [identity_fingerprint: {0}]",
                identityFingerprint);
            return Encoding.ASCII.GetString(
                Authority.DownloadFromRandomAuthority(
                    WellKnownUrlRetriever.GetMostRecentServerDescriptorPath(identityFingerprint, compressed),
                    compressed));
        }

        internal void Register(OnionRouter router)
        {
            if (null == router) { throw new ArgumentNullException(); }
            _onionRouterMap.Add(router.IdentityFingerprint, router);
        }

        internal void SetVoteDigest(Authority authority, string digest)
        {
            if (string.IsNullOrEmpty(digest)) {
                throw new ArgumentNullException();
            }
            if (!_authorities.Contains(authority)) {
                throw new ArgumentException();
            }
            _perAuthorityVoteDiget.Add(authority, digest);
        }

        private List<Authority> _authorities = new List<Authority>();
        protected Dictionary<string, OnionRouter> _onionRouterMap =
            new Dictionary<string, OnionRouter>();
        private Dictionary<Authority, string> _perAuthorityVoteDiget =
            new Dictionary<Authority, string>();
        private List<SignatureDescriptor> _signatureDescriptors =
            new List<SignatureDescriptor>();

        public class SearchCriteria
        {
            internal List<ushort> allowed_dir_ports = new List<ushort>();
            internal List<ushort> allowed_or_ports = new List<ushort>();
            internal List<OnionRouter> forbidden_onion_routers = new List<OnionRouter>();
            internal OnionRouter.StatusFlags flags;
        }
    }
}
