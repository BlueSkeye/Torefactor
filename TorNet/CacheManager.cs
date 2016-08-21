using System;
using System.IO;

using TorNet.Tor;

namespace TorNet
{
    internal static class CacheManager
    {
        static CacheManager()
        {
            _cacheBasePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        }
        
        /// <summary>Retrieve a fully qualified path for storage of the cached
        /// consensus.</summary>
        internal static string CachedConsensusFilePath
        {
            get
            {
                if (null == _cachedConsensusFilePath) {
                    _cachedConsensusFilePath = Path.Combine(_cacheBasePath, CachedConsensusFileName);
                }
                return _cachedConsensusFilePath;
            }
        }

        internal static string GetKeyCertificateFilePath(Authority authority)
        {
            return Path.Combine(_cacheBasePath, authority.Identity + CertificateExtension);
        }

        private const string CachedConsensusFileName = "cached-consensus";
        private const string CertificateExtension = ".cert";
        private static readonly string _cacheBasePath;
        private static string _cachedConsensusFilePath;
    }
}
