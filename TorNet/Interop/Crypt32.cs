using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TorNet.Interop
{
    internal static class Crypt32
    {
        [DllImport(DllName)]
        internal static extern bool CertFreeCertificateContext(
            [In] IntPtr /* PCCERT_CONTEXT*/ pCertContext);

        [DllImport(DllName)]
        internal static extern bool CryptBinaryToString(
            [In] byte[] pbBinary,
            [In] int cbBinary,
            [In] CrypBinaryFlags dwFlags,
            [In] byte[] pszString,
            [In, Out] ref int pcchString);

        [DllImport(DllName, CharSet = CharSet.Ansi)]
        internal static extern bool CryptDecodeObject(
            [In] int dwCertEncodingType,
            [In] string lpszStructType,
            [In] byte[] pbEncoded,
            [In] int cbEncoded,
            [In] int dwFlags,
            [In, Out] ref byte[] pvStructInfo,
            [In, Out] ref int pcbStructInfo);

        [DllImport(DllName, CharSet = CharSet.Ansi)]
        internal static extern bool CryptDecrypt(
            [In] IntPtr /* HCRYPTKEY */ hKey,
            [In] IntPtr /* HCRYPTHASH */ hHash,
            [In] bool Final,
            [In] int dwFlags,
            [In, Out] ref byte[] pbData,
            [In, Out] ref int pdwDataLen);

        [DllImport(DllName)]
        internal static extern bool CryptDestroyKey(
            [In] IntPtr /* HCRYPTKEY */ hKey);

        [DllImport(DllName)]
        internal static extern bool CryptEncrypt(
            [In] IntPtr /* HCRYPTKEY */ hKey,
            [In] IntPtr /* HCRYPTHASH */ hHash,
            [In] bool Final,
            [In] int dwFlags,
            [In, Out] ref byte[] pbData,
            [In, Out] ref int pdwDataLen,
            [In] int dwBufLen);

        [DllImport(DllName)]
        internal static extern bool CryptGetKeyParam(
            [In] IntPtr /* HCRYPTKEY */ hKey,
            [In] int dwParam,
            [In, Out] ref byte[] pbData,
            [In, Out] ref int pdwDataLen,
            [In] int dwFlags);

        [DllImport(DllName)]
        internal static extern bool CryptImportKey(
            [In] IntPtr /* HCRYPTPROV */ hProv,
            [In] IntPtr pbData,
            [In] int dwDataLen,
            [In] IntPtr /* HCRYPTKEY */ hPubKey,
            [In] int dwFlags,
            [Out] out IntPtr /* HCRYPTKEY */ phKey);
        [DllImport(DllName)]
        internal static extern bool CryptImportKey(
            [In] IntPtr /* HCRYPTPROV */ hProv,
            [In] byte[] pbData,
            [In] int dwDataLen,
            [In] IntPtr /* HCRYPTKEY */ hPubKey,
            [In] int dwFlags,
            [Out] out IntPtr /* HCRYPTKEY */ phKey);

        [DllImport(DllName)]
        internal static extern bool CryptSetKeyParam(
            [In] IntPtr /* HCRYPTKEY */ hKey,
            [In] int dwParam,
            [In] IntPtr pbData,
            [In] int dwFlags);

        [DllImport(DllName, CharSet = CharSet.Unicode)]
        internal static extern bool CryptStringToBinary(
            [In] string pszString,
            [In] int cchString,
            [In] CrypBinaryFlags dwFlags,
            [In] IntPtr pbBinary,
            [In, Out] ref int pcbBinary,
            [Out] out int pdwSkip,
            [Out] out int pdwFlags);

        private const string DllName = "Crypt32.DLL";
        internal const int CRYPT_OAEP = 0x00000040;
        internal const int KP_KEYLEN = 9;
        internal static readonly string PKCS_RSA_PRIVATE_KEY = ASCIIEncoding.ASCII.GetString(new byte[] { 43 });
        internal static readonly string RSA_CSP_PUBLICKEYBLOB = ASCIIEncoding.ASCII.GetString(new byte[] { 19 });
        internal const int X509_ASN_ENCODING = 0x00000001;
        internal const int PKCS_7_ASN_ENCODING = 0x00010000;

        [Flags]
        internal enum CrypBinaryFlags : uint
        {
            /// <summary>Base64, with certificate beginning and ending headers.</summary>
            Base64WithHeader = 0x00000000,
            /// <summary>Base64, without headers.</summary>
            Base64 = 0x00000001,
            /// <summary>Pure binary copy.</summary>
            Binary = 0x00000002,
            /// <summary>Base64, with request beginning and ending headers.</summary>
            Base64WithRequestHeader = 0x00000003,
            /// <summary>Hexadecimal only.</summary>
            Hexadecimal = 0x00000004,
            /// <summary>Hexadecimal, with ASCII character display.</summary>
            HexadecimalWithAscii = 0x00000005,
            /// <summary>Tries the following, in order: Base64WithHeader, Base64</summary>
            /// <remarks>CryptStringToBinary only.</remarks>
            AnyBase64 = 0x00000006,
            /// <summary>Tries the following, in order: Base64WithHeader, Base64, Binary</summary>
            /// <remarks>CryptStringToBinary only.</remarks>
            AnyString = 0x00000007,
            /// <summary>Tries the following, in order: HexadecimalWithAddress,
            /// HexadecimalWithAsciiAndAddress, Hexadecimal, RawHexadecimal, 
            /// HexadecimalWithAscii</summary>
            /// <remarks>CryptStringToBinary only.</remarks>
            AnyHexadecimal = 0x00000008,
            /// <summary>Base64, with X.509 CRL beginning and ending headers.</summary>
            Base64WithX509CRLHeader = 0x00000009,
            /// <summary>Hexadecimal, with address display.</summary>
            HexadecimalWithAddress = 0x0000000a,
            /// <summary>Hexadecimal, with ASCII character and address display.</summary>
            HexadecimalWithAsciiAndAddress = 0x0000000b,
            /// <summary>A raw hexadecimal string.
            /// Windows Server 2003 and Windows XP:  This value is not supported.</summary>
            RawHexadecimal = 0x0000000c,

            /// <summary>Enforce strict decoding of ASN.1 text formats. Some ASN.1 binary
            /// BLOBS can have the first few bytes of the BLOB incorrectly interpreted as
            /// Base64 text. In this case, the rest of the text is ignored.Use this flag
            /// to enforce complete decoding of the BLOB.
            /// Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:
            /// This value is not supported./// </summary>
            Strict = 0x20000000,

            /// <summary>Do not append any new line characters to the encoded string.
            /// The default behavior is to use a carriage return/line feed(CR/LF) pair
            /// (0x0D/0x0A) to represent a new line.
            /// Windows Server 2003 and Windows XP:  This value is not supported.</summary>
            /// <remarks>CryptBinaryToString only.</remarks>
            NoCRLF = 0x40000000,
            /// <summary>Only use the line feed (LF) character(0x0A) for a new line.
            /// The default behavior is to use a CR/LF pair(0x0D/0x0A) to represent a
            /// new line.</summary>
            /// <remarks>CryptBinaryToString only.</remarks>
            NoCR = 0x80000000,
        }
    }
}
