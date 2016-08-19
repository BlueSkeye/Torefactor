
namespace TorNet
{
    internal static class Constants
    {
        // tor-spec 0.3
        //
        // As an optimization, implementations SHOULD choose DH private keys (x) of
        // 320 bits.
        internal const int DH_LEN = 128;
        internal const int DH_SEC_LEN = 40;
        internal const int HASH_LEN = 20;
    }
}
