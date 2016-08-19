using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TorNet.Tor
{
    internal class Authority
    {
        static Authority()
        {
            /// <summary>Hardcoded list of authorities.
            /// TODO : These long strings are easily spottable by various firewalls and
            /// filtering proxies. Some kind of encoding should be applied here.</summary>
            /// <remarks>Responsivness is as of our testing (summer 2016)</remarks>
            List<Authority> authorities = new List<Authority>();
#if !PROXIED
            /* responsive */
            authorities.Add(
                Create("moria1", "D586D18309DED4CD6D57C18FDB97EFA96D330566", IPAddress.Parse("128.31.0.39"), 9131, 9101)
                    .AddAdditionalPorts("9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31"));
#endif
            /* responsive */
            authorities.Add(
                Create("tor26", "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4", IPAddress.Parse("86.59.21.38"), 80, 443)
                   .AddAdditionalPorts("847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D"));
            /* responsive */
            authorities.Add(
                Create("dizum", "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58", IPAddress.Parse("194.109.206.212"), 80, 443)
                    .AddAdditionalPorts("7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755"));
            /* Strange identity :-) */
            authorities.Add(
                Create("Tonga", "bridge", IPAddress.Parse("82.94.251.203"), 80, 443)
                    .AddAdditionalPorts("4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D"));
            ///* unresponsive */
            //authorities.Add(
            //    Create("turtles", "27B6B5996C426270A5C95488AA5BCEB6BCC86956", IPAddress.Parse("76.73.17.194"), 9030, 9090)
            //        .AddAdditionalPorts("F397 038A DC51 3361 35E7 B80B D99C A384 4360 292B"));
#if !PROXIED
            ///* unresponsive */
            //authorities.Add(
            //    Create("gabelmoo", "ED03BB616EB2F60BEC80151114BB25CEF515B226", IPAddress.Parse("212.112.245.170"), 80, 443)
            //    .AddAdditionalPorts("F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281"));
#endif
            /* responsive */
            authorities.Add(
                Create("dannenberg", "585769C78764D58426B8B52B6651A5A71137189A", IPAddress.Parse("193.23.244.244"), 80, 443)
                    .AddAdditionalPorts("7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123"));
            // Removed as per Tor 0.2.8.6
            // "urras orport=80 v3ident=80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34:443 0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417",
#if !PROXIED
            /* responsive */
            // Strange inversion of ports. */
            authorities.Add(
                Create("maatuska", "49015F787433103580E3B66A1707A00E60F2D15B", IPAddress.Parse("171.25.193.9"), 443, 80)
                    .AddAdditionalPorts("BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810"));
#endif
#if !PROXIED
            /* ??? */
            authorities.Add(
                Create("Faravahar", "EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97", IPAddress.Parse("154.35.32.5"), 80, 443)
                    .AddAdditionalPorts("CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC"));
#endif
            KnownAuthorities = authorities.ToArray();
        }

        internal Authority(string nickname, string identity, string hostName, IPAddress ip, ushort dirport,
            ushort mainORPort)
        {
            NickName = nickname;
            Identity = identity;
            HostName = hostName;
            IPAddress = ip;
            DirPort = dirport;
            ORPorts = new List<ushort>();
            ORPorts.Add(mainORPort);
        }

        internal string Contact { get; set; }
        internal ushort DirPort { get; private set; }
        internal string HostName { get; private set; }
        internal string Identity { get; private set; }
        internal IPAddress IPAddress { get; private set; }
        internal string IPV6Address { get; private set; }
        internal string NickName { get; private set; }
        internal List<ushort> ORPorts { get; private set; }

        // TODO : Utility function. Make this less obvious for detection.
        private Authority AddAdditionalPorts(string list)
        {
            string[] candidates = list.Split(' ');
            foreach(string candidate in candidates) {
                ushort port = ushort.Parse(candidate, NumberStyles.AllowHexSpecifier);
            }
            return this;
        }

        private static Authority Create(string nickname, string identity, IPAddress ip,
            ushort dirport, ushort mainORPort)
        {
            Authority result = new Authority(nickname, identity, null, ip, dirport, mainORPort);
            result.ORPorts = new List<ushort>();
            return result;
        }

        internal Task<string> DownloadContent(string path, bool compressed)
        {
            if (!compressed) {
                return Helpers.HttpGetStringContent(IPAddress.ToString(), DirPort, path);
            }
            Task<byte[]> compressedResult = Helpers.HttpGetBinaryContent(IPAddress.ToString(), DirPort, path);

            //using (FileStream trash = File.Open(Helpers.DecompressionTestFilePath, FileMode.Create, FileAccess.Write)) {
            //    trash.Write(result.Result, 0, result.Result.Length);
            //}
            return Task<string>.Run<string>(delegate() {
                return Encoding.ASCII.GetString(Helpers.Uncompress(compressedResult.Result));
            });
        }

        /// <summary>Randomly select an authority in the hardccoded list and
        /// download current consensus from a well known path.</summary>
        /// <param name="path"></param>
        /// <returns></returns>
        internal static string DownloadFromRandomAuthority(string path, bool compressed)
        {
            Globals.LogInfo("consensus::download_from_random_authority() [path: {0}]", path);
            return GetRandomAuthority().DownloadContent(path, compressed).Result;
        }

        internal static Authority GetRandomAuthority()
        {
            // TODO : Once bootstrapping occured we can widden the authority range and
            // draw from a wider set.
            int authorityIndex;
            using (RandomNumberGenerator randomizer = RandomNumberGenerator.Create()) {
                byte[] buffer = new byte[sizeof(ulong)];
                randomizer.GetBytes(buffer);
                authorityIndex = (int)(buffer.ToUInt64() % (ulong)Authority.KnownAuthorities.Length);
            }
            return KnownAuthorities[authorityIndex];
        }

        /// <summary>A collection of well known authoriies.</summary>
        internal static readonly Authority[] KnownAuthorities;
    }
}
