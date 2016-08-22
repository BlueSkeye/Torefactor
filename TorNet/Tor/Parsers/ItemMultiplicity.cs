
namespace TorNet.Tor.Parsers
{
    /// <summary>As of 1.2 from dirspec.txt</summary>
    internal enum ItemMultiplicity
    {
        Undefined = 0,
        AtStartExactlyOnce,
        ExactlyOnce,
        AtEndExactlyOnce,
        AtMotOnce,
        AnyNumber,
        OnceOrMore,
    }
}
