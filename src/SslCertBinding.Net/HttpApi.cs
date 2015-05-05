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
			public uint DefaultCertCheckMode;
			public int DefaultRevocationFreshnessTime;
			public int DefaultRevocationUrlRetrievalTimeout;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pDefaultSslCtlIdentifier;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pDefaultSslCtlStoreName;
			public uint DefaultFlags;
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

		#endregion

		#region Constants

		public const uint HTTP_INITIALIZE_CONFIG = 0x00000002;
		public const uint HTTP_SERVICE_CONFIG_SSL_FLAG_NEGOTIATE_CLIENT_CERT = 0x00000002;
		public const uint HTTP_SERVICE_CONFIG_SSL_FLAG_NO_RAW_FILTER = 0x00000004;
		public const uint NOERROR = 0;
		public const uint ERROR_INSUFFICIENT_BUFFER = 122;
		public const uint ERROR_ALREADY_EXISTS = 183;
		public const uint ERROR_FILE_NOT_FOUND = 2;
		public const int ERROR_NO_MORE_ITEMS = 259;

		#endregion

		private static readonly HTTPAPI_VERSION HttpApiVersion = new HTTPAPI_VERSION(1, 0);
	}
}
