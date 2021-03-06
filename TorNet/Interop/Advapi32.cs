﻿using System;
using System.Runtime.InteropServices;

namespace TorNet.Interop
{
    internal static class Advapi32
    {
        [DllImport(DllName, CharSet = CharSet.Unicode)]
        internal static extern bool CryptAcquireContext(
            [Out] out IntPtr /* HCRYPTPROV* */ phProv,
            [In] string pszContainer,
            [In] string pszProvider,
            [In] int dwProvType,
            [In] ContextCreationFlags dwFlags
        );

        [DllImport(DllName)]
        internal static extern bool CryptCreateHash(
            [In] IntPtr /* HCRYPTPROV */ hProv,
            [In] int Algid,
            [In] IntPtr /* HCRYPTKEY */ hKey,
            [In] int dwFlags,
            [Out] out IntPtr /* HCRYPTHASH * */ phHash);

        [DllImport(DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CryptDecodeObjectEx(
            [In] CertificateEncodingType dwCertEncodingType,
            [In] IntPtr /* LPCSTR */ lpszStructType,
            [In] byte[] pbEncoded,
            [In] int cbEncoded,
            [In] EncodingFlags dwFlags,
            [In] IntPtr /* PCRYPT_DECODE_PARA */ pDecodePara,
            [In,Out] ref IntPtr pvStructInfo,
            [In,Out] ref int pcbStructInfo);

        [DllImport(DllName)]
        internal static extern bool CryptVerifySignature(
            [In] IntPtr /* HCRYPTHASH */ hHash,
            [In] IntPtr pbSignature,
            [In] int dwSigLen,
            [In] IntPtr /* HCRYPTKEY */ hPubKey,
            [In] IntPtr /* LPCTSTR */ sDescription,
            [In] SignatureVerificationFlags dwFlags);

        [DllImport(DllName)]
        internal static extern bool CryptDestroyHash(
            [In] IntPtr /* HCRYPTHASH */ hHash);

        [DllImport(DllName)]
        internal static extern bool CryptDestroyKey(
            [In] IntPtr /* HCRYPTKEY */ hKey);

        [DllImport(DllName)]
        internal static extern bool CryptDuplicateHash(
            [In] IntPtr /* HCRYPTHASH */ hHash,
            [In] IntPtr pdwReserved,
            [In] int dwFlags,
            [Out] out IntPtr /* HCRYPTHASH* */phHash);

        [DllImport(DllName)]
        internal static extern bool CryptGetHashParam(
            [In] IntPtr /* HCRYPTHASH */ hHash,
            [In] int dwParam,
            [In] IntPtr pbData,
            [In, Out] ref int pdwDataLen,
            [In] int dwFlags);

        [DllImport(DllName)]
        internal static extern bool CryptGenRandom(
            [In] IntPtr /* HCRYPTPROV */ hProv,
            [In] int dwLen,
            [In] byte[] pbBuffer);

        [DllImport(DllName)]
        internal static extern bool CryptHashData(
            [In] IntPtr /* HCRYPTHASH */ hHash,
            [In] byte[] pbData,
            [In] int dwDataLen,
            [In] int dwFlags);

        [DllImport(DllName, CharSet = CharSet.Unicode)]
        internal static extern bool CryptReleaseContext(
            [In] IntPtr /* HCRYPTPROV */ hProv,
            [In] int dwFlags);

        private const string DllName = "Advapi32.DLL";
        internal const int RsaAesProvider = 24;
        internal const string RsaAesProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider";
        internal const string RsaAesXpProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)";
        internal const int CALG_SHA1 = (4 << 13) | (0) | 4;
        internal const short HP_HASHVAL = 0x0002;

        [Flags()]
        internal enum ContextCreationFlags : uint
        {
            VerifyContect = 0xF0000000,
            NewKeyset = 0x00000008,
            DeleteKeyset = 0x00000010,
            MachineKeyset = 0x00000020,
            Silent = 0x00000040,
            DefaultContainerOptional = 0x00000080
        }

        [Flags()]
        internal enum EncodingFlags
        {
            AllocateMemory = 0x8000,
            EnableUnicodeDecoding = 0x2000000,
            NoCopy = 1,
            DecodeToBeSingeOnly = 2,
            ShareOIDStrings = 4,
            DoNotReverseSignatureBytes = 8,
        }

        [Flags()]
        internal enum SignatureVerificationFlags : uint
        {
            NoHashOID = 0x00000001,
            // Unused
            Type2Format = 0x00000002,
            X931Format = 0x00000004
        }
    }
}
