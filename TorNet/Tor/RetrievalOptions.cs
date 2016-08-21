using System;

namespace TorNet.Tor
{
    [Flags()]
    internal enum RetrievalOptions
    {
        None = 0,
        /// <summary>Will attempt to find the content in cache first if force
        /// download is not in action. If download is triggered for whatever reason,
        /// the result will be stored in cache if found.</summary>
        UseCache = 0x01,
        /// <summary>Prevent any use of the cache. No search will be performed in
        /// cache and in case a download is triggered the result if found won't be
        /// stored in cache.</summary>
        DoNotUseCache = 0x02,
        /// <summary>Force content downloading.</summary>
        ForceDownload = 0x04,
    }
}
