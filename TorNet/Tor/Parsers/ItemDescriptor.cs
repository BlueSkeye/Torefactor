
namespace TorNet.Tor.Parsers
{
    internal class ItemDescriptor<PS>
    {
        internal ItemDescriptor(PS state, ItemMultiplicity multiplicity)
        {
            ParserState = state;
            Multiplicity = multiplicity;
        }

        internal ItemMultiplicity Multiplicity { get; private set; }
        internal PS ParserState { get; private set; }
    }
}
