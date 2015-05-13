using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SslCertBinding.Net
{
	internal class HttpApi
	{
		// ReSharper disable InconsistentNaming

		public static void ThrowWin32ExceptionIfError(uint retVal) {
			if (NOERROR != retVal) {
				throw new Win32Exception(Convert.ToInt32(retVal));
			}
		}

		public static void CallHttpApi(Action body) {
			uint retVal = HttpInitialize(HttpApiVersion, HTTP_INITIALIZE_CONFIG, IntPtr.Zero);
			ThrowWin32ExceptionIfError(retVal);

			try {
				body();
			} finally {
				HttpTerminate(HTTP_INITIALIZE_CONFIG, IntPtr.Zero);
			}
		}

		public delegate void Action();

		#region DllImport

		[DllImport("httpapi.dll", SetLastError = true)]
		public static extern uint HttpInitialize(
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
			uint Flags,
			IntPtr pReserved);

		[DllImport("httpapi.dll", SetLastError = true)]
		public static extern uint HttpQueryServiceConfiguration(
				IntPtr serviceIntPtr,
				HTTP_SERVICE_CONFIG_ID configId,
				IntPtr pInputConfigInfo,
				int inputConfigInfoLength,
				IntPtr pOutputConfigInfo,
				int outputConfigInfoLength,
				[Optional]
				out int pReturnLength,
				IntPtr pOverlapped);


		public enum HTTP_SERVICE_CONFIG_ID
		{
			HttpServiceConfigIPListenList = 0,
			HttpServiceConfigSSLCertInfo,
			HttpServiceConfigUrlAclInfo,
			HttpServiceConfigMax
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
			public IntPtr pIpPort;

			public HTTP_SERVICE_CONFIG_SSL_KEY(IntPtr pIpPort) {
				this.pIpPort = pIpPort;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct HTTP_SERVICE_CONFIG_SSL_PARAM
		{
			public int SslHashLength;
			public IntPtr pSslHash;
			public Guid AppId;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pSslCertStoreName;
			public CertCheckModes DefaultCertCheckMode;
			public int DefaultRevocationFreshnessTime;
			public int DefaultRevocationUrlRetrievalTimeout;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pDefaultSslCtlIdentifier;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pDefaultSslCtlStoreName;
			public HTTP_SERVICE_CONFIG_SSL_FLAG DefaultFlags;
		}

		[StructLayout(LayoutKind.Sequential, Pack = 2)]
		public struct HTTPAPI_VERSION
		{
			public ushort HttpApiMajorVersion;
			public ushort HttpApiMinorVersion;

			public HTTPAPI_VERSION(ushort majorVersion, ushort minorVersion) {
				HttpApiMajorVersion = majorVersion;
				HttpApiMinorVersion = minorVersion;
			}
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct HTTP_SERVICE_CONFIG_SSL_QUERY
		{
			public HTTP_SERVICE_CONFIG_QUERY_TYPE QueryDesc;
			public HTTP_SERVICE_CONFIG_SSL_KEY KeyDesc;
			public uint dwToken;
		}

		public enum HTTP_SERVICE_CONFIG_QUERY_TYPE
		{
			HttpServiceConfigQueryExact = 0,
			HttpServiceConfigQueryNext,
			HttpServiceConfigQueryMax
		}

		/// <summary>
		/// Determines how client certificates are checked. 
		/// </summary>
		[Flags]
		public enum CertCheckModes : uint
		{
			/// <summary>
			/// Enables the client certificate revocation check.
			/// </summary>
			None = 0,

			/// <summary>
			/// Client certificate is not to be verified for revocation. 
			/// </summary>
			DoNotVerifyCertificateRevocation = 1,

			/// <summary>
			/// Only cached certificate is to be used the revocation check. 
			/// </summary>
			VerifyRevocationWithCachedCertificateOnly = 2,

			/// <summary>
			/// The RevocationFreshnessTime setting is enabled.
			/// </summary>
			EnableRevocationFreshnessTime = 4,

			/// <summary>
			/// No usage check is to be performed.
			/// </summary>
			NoUsageCheck = 0x10000
		}

		[Flags]
		public enum HTTP_SERVICE_CONFIG_SSL_FLAG : uint
		{
			NONE = 0,

			/// <summary>
			/// Client certificates are mapped where possible to corresponding operating-system user accounts based on the certificate mapping rules stored in Active Directory.
			/// </summary>
			USE_DS_MAPPER = 0x00000001,

			/// <summary>
			/// Enables a client certificate to be cached locally for subsequent use.
			/// </summary>
			NEGOTIATE_CLIENT_CERT = 0x00000002,

			/// <summary>
			/// Prevents SSL requests from being passed to low-level ISAPI filters.
			/// </summary>
			NO_RAW_FILTER = 0x00000004,
		}

		#endregion

		#region Constants

		public const uint HTTP_INITIALIZE_CONFIG = 0x00000002;
		public const uint NOERROR = 0;
		public const uint ERROR_INSUFFICIENT_BUFFER = 122;
		public const uint ERROR_ALREADY_EXISTS = 183;
		public const uint ERROR_FILE_NOT_FOUND = 2;
		public const int ERROR_NO_MORE_ITEMS = 259;

		#endregion

		private static readonly HTTPAPI_VERSION HttpApiVersion = new HTTPAPI_VERSION(1, 0);
	}
}
