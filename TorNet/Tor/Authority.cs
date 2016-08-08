using System.Net;

namespace TorNet.Tor
{
    internal class Authority
    {
        internal Authority(string nickname, string identity, string address, IPAddress ip,
            ushort dirport, ushort orport)
        {
            NickName = nickname;
            Identity = identity;
            Address = address;
            IPAddress = ip;
            DirPort = dirport;
            ORPort = orport;
        }

        internal string Address { get; private set; }
        internal string Contact { get; set; }
        internal ushort DirPort { get; private set; }
        internal string Identity { get; private set; }
        internal IPAddress IPAddress { get; private set; }
        internal string NickName { get; private set; }
        internal ushort ORPort { get; private set; }
    }
}
