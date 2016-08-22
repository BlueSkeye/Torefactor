using System;
using System.Runtime.InteropServices;

namespace TorNet
{
    public class InteropException : ApplicationException
    {
        internal InteropException()
            : this(LastWindowsError)
        {
            return;
        }

        internal InteropException(int lastError)
            : base(FormatMessage(lastError))
        {
            return;
        }

        // TODO : Might be inaccurate. Retrieval might be performed much later
        // than original error.
        private static int LastWindowsError
        {
            get { return Marshal.GetLastWin32Error(); }
        }

        private static string FormatMessage(int lastError)
        {
            try { return string.Format("WIndows error 0x{0:X8}", lastError); }
            catch { return "UNKNOWN ERROR"; }
        }
    }
}
