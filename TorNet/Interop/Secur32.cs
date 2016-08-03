using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace TorNet.Interop
{
    internal static class Secur32
    {
        [DllImport(DllName)]
        internal static extern int FreeContextBuffer(
            [In] IntPtr pvContextBuffer);

        /// <summary></summary>
        /// <returns></returns>
        /// <remarks>The CharSet property is important. We want the functions from
        /// the interface to receive Unicode strings.</remarks>
        [DllImport(DllName, CharSet = CharSet.Unicode)]
        internal static extern IntPtr InitSecurityInterface();

        private const string DllName = "SECUR32.DLL";
    }
}
