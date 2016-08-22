using System.Security.Cryptography;

using TorNet.Interop;

namespace TorNet.Cryptography
{
    public class CryptographyException : CryptographicException
    {
        internal CryptographyException(WinErrors nativeError)
            : base(string.Format("Error {0}.", nativeError))
        {
            return;
        }
    }
}
