using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TorNet.Interop
{
    internal class InteropHelpers
    {
        internal static IntPtr GetWellKnownOIDPointer(WellKnownOIDs oid)
        {
            return new IntPtr((int)oid);
        }

        internal enum WellKnownOIDs
        {
            X509PublicKeyInfo = 8,
        }
    }
}
