using System;

namespace TorNet.Interop
{
    internal enum WinErrors : uint
    {
        OK = 0,
        InvalidParameter = 87,
        BadUID /* NTE_BAD_UID */ = 0x80090001,
        BadHash /* NTE_BAD_HASH*/ = 0x80090002,
        BadKey /* NTE_BAD_KEY */ = 0x80090003,
        BadSignature /* NTE_BAD_SIGNATURE */ = 0x80090006,
        InvalidFlags /* NTE_BAD_FLAGS */ = 0x80090009,
        NoMemory /* NTE_NOçMEMORY */ = 0x8009000E,
        InvalidHandle = 0x80090301,
        InternalError = 0x80090304,
        InvalidToken = 0x80090308,
        ContinuationNeeded = 0x00090312,
        IncompleteMessage = 0x80090318,
        IncompleteCredentials = 0x80090320,
        UntrustedRoot = 0x80090325,
    }
}
