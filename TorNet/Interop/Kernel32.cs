using System;
using System.Runtime.InteropServices;

namespace TorNet.Interop
{
    internal static class Kernel32
    {
        [DllImport(DllName, SetLastError = true)]
        internal static extern IntPtr LocalFree(
            [In] IntPtr hMem);

        private const string DllName = "Kernel32.DLL";
    }
}
