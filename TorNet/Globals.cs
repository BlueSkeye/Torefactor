using System;

namespace TorNet
{
    internal static class Globals
    {
        internal static void Assert(bool condition)
        {
            if (condition) { return; }
            // was mini_assert
            throw new InvalidOperationException();
        }

        internal static void LogInfo(string message, params object[] args)
        {
            // TODO
            return;
        }

        internal const Endianness DefaultEndianness = Endianness.little_endian;
    }
}
