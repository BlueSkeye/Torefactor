using System;

namespace TorNet.Interop
{
    internal enum WinErrors : uint
    {
        OK = 0,
        InvalidHandle = 0x80090301,
        InternalError = 0x80090304,
        InvalidToken = 0x80090308,
        ContinuationNeeded = 0x00090312,
        IncompleteMessage = 0x80090318,
        IncompleteCredentials = 0x80090320,
        UntrustedRoot = 0x80090325,
    }
}
