using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using SslCertBinding.Net.Internal;

namespace SslCertBinding.Net.Internal.Interop
{
    internal static class HttpApi
    {
        public static void ThrowWin32ExceptionIfError(uint retVal)
        {
            if (NOERROR != retVal)
            {
                throw new Win32Exception(Convert.ToInt32(retVal));
            }
        }

        public static void CallHttpApi(Action body)
        {
            const uint flags = HTTP_INITIALIZE_CONFIG;
            PlatformHelpers.ThrowIfNotWindows();

            try
            {
                uint retVal = HttpInitialize(HttpApiVersion, flags, IntPtr.Zero);
                ThrowWin32ExceptionIfError(retVal);
            }
            catch (DllNotFoundException ex)
            {
                throw PlatformHelpers.CreateWindowsOnlyException(ex);
            }

            try
            {
                body();
            }
            finally
            {
                uint retVal = HttpTerminate(flags, IntPtr.Zero);
                ThrowWin32ExceptionIfError(retVal);
            }
        }

        [DllImport("httpapi.dll", SetLastError = true)]
        private static extern uint HttpInitialize(
            HTTPAPI_VERSION version,
            uint flags,
            IntPtr pReserved);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpSetServiceConfiguration(
            IntPtr serviceIntPtr,
            HTTP_SERVICE_CONFIG_ID configId,
            IntPtr pConfigInformation,
            int configInformationLength,
            IntPtr pOverlapped);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpDeleteServiceConfiguration(
            IntPtr serviceIntPtr,
            HTTP_SERVICE_CONFIG_ID configId,
            IntPtr pConfigInformation,
            int configInformationLength,
            IntPtr pOverlapped);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpTerminate(
            uint flags,
            IntPtr pReserved);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpQueryServiceConfiguration(
            IntPtr serviceIntPtr,
            HTTP_SERVICE_CONFIG_ID configId,
            IntPtr pInputConfigInfo,
            int inputConfigInfoLength,
            IntPtr pOutputConfigInfo,
            int outputConfigInfoLength,
            [Optional] out int pReturnLength,
            IntPtr pOverlapped);

        public enum HTTP_SERVICE_CONFIG_ID
        {
            HttpServiceConfigIPListenList = 0,
            HttpServiceConfigSSLCertInfo,
            HttpServiceConfigUrlAclInfo,
            HttpServiceConfigTimeout,
            HttpServiceConfigCache,
            HttpServiceConfigSslSniCertInfo,
            HttpServiceConfigSslCcsCertInfo,
            HttpServiceConfigSetting,
            HttpServiceConfigSslCertInfoEx,
            HttpServiceConfigSslSniCertInfoEx,
            HttpServiceConfigSslCcsCertInfoEx,
            HttpServiceConfigSslScopedCcsCertInfo,
            HttpServiceConfigSslScopedCcsCertInfoEx,
            HttpServiceConfigMax,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_SSL_SET
        {
            public HTTP_SERVICE_CONFIG_SSL_KEY KeyDesc;
            public HTTP_SERVICE_CONFIG_SSL_PARAM ParamDesc;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_SSL_KEY
        {
            public HTTP_SERVICE_CONFIG_SSL_KEY(IntPtr pIpPort)
            {
                this.pIpPort = pIpPort;
            }

            public IntPtr pIpPort;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_SSL_QUERY
        {
            public HTTP_SERVICE_CONFIG_QUERY_TYPE QueryDesc;
            public HTTP_SERVICE_CONFIG_SSL_KEY KeyDesc;
            public uint dwToken;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_SSL_CCS_SET
        {
            public HTTP_SERVICE_CONFIG_SSL_CCS_KEY KeyDesc;
            public HTTP_SERVICE_CONFIG_SSL_PARAM ParamDesc;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_SSL_CCS_KEY
        {
            public SOCKADDR_STORAGE LocalAddress;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_SSL_CCS_QUERY
        {
            public HTTP_SERVICE_CONFIG_QUERY_TYPE QueryDesc;
            public HTTP_SERVICE_CONFIG_SSL_CCS_KEY KeyDesc;
            public uint dwToken;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_SSL_SNI_SET
        {
            public HTTP_SERVICE_CONFIG_SSL_SNI_KEY KeyDesc;
            public HTTP_SERVICE_CONFIG_SSL_PARAM ParamDesc;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_SSL_SNI_KEY
        {
            public SOCKADDR_STORAGE IpPort;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string? Host;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_SSL_SNI_QUERY
        {
            public HTTP_SERVICE_CONFIG_QUERY_TYPE QueryDesc;
            public HTTP_SERVICE_CONFIG_SSL_SNI_KEY KeyDesc;
            public uint dwToken;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct HTTP_SERVICE_CONFIG_SSL_PARAM
        {
            public int SslHashLength;
            public IntPtr pSslHash;
            public Guid AppId;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pSslCertStoreName;

            public CertCheckModes DefaultCertCheckMode;
            public int DefaultRevocationFreshnessTime;
            public int DefaultRevocationUrlRetrievalTimeout;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pDefaultSslCtlIdentifier;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pDefaultSslCtlStoreName;

            public HTTP_SERVICE_CONFIG_SSL_FLAG DefaultFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SOCKADDR_STORAGE
        {
            public short ss_family;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] __ss_pad1;

            public long __ss_align;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 112)]
            public byte[] __ss_pad2;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        public struct HTTPAPI_VERSION
        {
            public HTTPAPI_VERSION(ushort majorVersion, ushort minorVersion)
            {
                HttpApiMajorVersion = majorVersion;
                HttpApiMinorVersion = minorVersion;
            }

            public ushort HttpApiMajorVersion;
            public ushort HttpApiMinorVersion;
        }

        public enum HTTP_SERVICE_CONFIG_QUERY_TYPE
        {
            HttpServiceConfigQueryExact = 0,
            HttpServiceConfigQueryNext,
            HttpServiceConfigQueryMax,
        }

        [Flags]
        public enum CertCheckModes : uint
        {
            None = 0,
            DoNotVerifyCertificateRevocation = 1,
            VerifyRevocationWithCachedCertificateOnly = 2,
            EnableRevocationFreshnessTime = 4,
            NoUsageCheck = 0x10000,
        }

        [Flags]
        public enum HTTP_SERVICE_CONFIG_SSL_FLAG : uint
        {
            NONE = 0,
            USE_DS_MAPPER = 0x00000001,
            NEGOTIATE_CLIENT_CERT = 0x00000002,
            NO_RAW_FILTER = 0x00000004,
            DISABLE_TLS_1_2 = 0x00001000,
        }

        public const uint HTTP_INITIALIZE_CONFIG = 0x00000002;
        public const uint NOERROR = 0;
        public const uint ERROR_INSUFFICIENT_BUFFER = 122;
        public const uint ERROR_ALREADY_EXISTS = 183;
        public const uint ERROR_FILE_NOT_FOUND = 2;
        public const uint ERROR_INVALID_PARAMETER = 87;
        public const int ERROR_NO_MORE_ITEMS = 259;

        private static readonly HTTPAPI_VERSION HttpApiVersion = new(1, 0);
    }
}
