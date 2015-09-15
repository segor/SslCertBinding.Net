using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace SslCertBinding.Net
{
	public class CertificateBindingConfiguration : ICertificateBindingConfiguration
	{
		public CertificateBinding[] Query(IPEndPoint ipPort = null) {
			if (ipPort == null) 
				return QueryInternal();

			var info = QueryExact(ipPort);
			return info == null ? new CertificateBinding[0] : new[] { info };
		}

		public bool Bind(CertificateBinding binding) {
			bool bindingUpdated = false;
			HttpApi.CallHttpApi(
				delegate {

					GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(binding.IpPort);
					IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();
					var httpServiceConfigSslKey = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);

					byte[] hash = GetHash(binding.Thumbprint);
					GCHandle handleHash = GCHandle.Alloc(hash, GCHandleType.Pinned);
					var options = binding.Options;
					var configSslParam = new HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM {
						AppId = binding.AppId,
						DefaultCertCheckMode = (options.DoNotVerifyCertificateRevocation ? HttpApi.CertCheckModes.DoNotVerifyCertificateRevocation : 0)
							| (options.VerifyRevocationWithCachedCertificateOnly ? HttpApi.CertCheckModes.VerifyRevocationWithCachedCertificateOnly : 0)
							| (options.EnableRevocationFreshnessTime ? HttpApi.CertCheckModes.EnableRevocationFreshnessTime : 0)
							| (options.NoUsageCheck ? HttpApi.CertCheckModes.NoUsageCheck : 0),
						DefaultFlags = (options.NegotiateCertificate ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NEGOTIATE_CLIENT_CERT : 0)
							| (options.UseDsMappers ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.USE_DS_MAPPER : 0)
							| (options.DoNotPassRequestsToRawFilters ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NO_RAW_FILTER : 0),
						DefaultRevocationFreshnessTime = (int)options.RevocationFreshnessTime.TotalSeconds,
						DefaultRevocationUrlRetrievalTimeout = (int)options.RevocationUrlRetrievalTimeout.TotalMilliseconds,
						pSslCertStoreName = binding.StoreName,
						pSslHash = handleHash.AddrOfPinnedObject(),
						SslHashLength = hash.Length,
						pDefaultSslCtlIdentifier = options.SslCtlIdentifier,
						pDefaultSslCtlStoreName = options.SslCtlStoreName
					};

					var configSslSet = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SET {
						ParamDesc = configSslParam,
						KeyDesc = httpServiceConfigSslKey
					};

					IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
						Marshal.SizeOf(typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET)));
					Marshal.StructureToPtr(configSslSet, pInputConfigInfo, false);

					try {
						uint retVal = HttpApi.HttpSetServiceConfiguration(IntPtr.Zero,
							HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
							pInputConfigInfo,
							Marshal.SizeOf(configSslSet),
							IntPtr.Zero);

						if (HttpApi.ERROR_ALREADY_EXISTS != retVal) {
							HttpApi.ThrowWin32ExceptionIfError(retVal);
						} else {
							retVal = HttpApi.HttpDeleteServiceConfiguration(IntPtr.Zero,
								HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
								pInputConfigInfo,
								Marshal.SizeOf(configSslSet),
								IntPtr.Zero);
							HttpApi.ThrowWin32ExceptionIfError(retVal);

							retVal = HttpApi.HttpSetServiceConfiguration(IntPtr.Zero,
								HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
								pInputConfigInfo,
								Marshal.SizeOf(configSslSet),
								IntPtr.Zero);
							HttpApi.ThrowWin32ExceptionIfError(retVal);
							bindingUpdated = true;
						}
					} finally {
						Marshal.FreeCoTaskMem(pInputConfigInfo);
						if (handleHash.IsAllocated)
							handleHash.Free();
						if (sockAddrHandle.IsAllocated)
							sockAddrHandle.Free();
					}
				});
			return bindingUpdated;
		}

		public void Delete(IPEndPoint endPoint) {
			Delete(new[] { endPoint });
		}

		public void Delete(IPEndPoint[] endPoints) {
			if (endPoints == null)
				throw new ArgumentNullException("endPoints");
			if (endPoints.Length == 0)
				return;

			HttpApi.CallHttpApi(
			delegate {
				foreach (var ipPort in endPoints) {
					GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(ipPort);
					IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();
					HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY httpServiceConfigSslKey = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);

					var configSslSet = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SET {
						KeyDesc = httpServiceConfigSslKey
					};

					IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
							Marshal.SizeOf(typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET)));
					Marshal.StructureToPtr(configSslSet, pInputConfigInfo, false);

					try {
						uint retVal = HttpApi.HttpDeleteServiceConfiguration(IntPtr.Zero,
							HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
							pInputConfigInfo,
							Marshal.SizeOf(configSslSet),
							IntPtr.Zero);
						HttpApi.ThrowWin32ExceptionIfError(retVal);
					} finally {
						Marshal.FreeCoTaskMem(pInputConfigInfo);
						if (sockAddrHandle.IsAllocated)
							sockAddrHandle.Free();
					}
				}
			});
		}

		private static CertificateBinding QueryExact(IPEndPoint ipPort) {
			CertificateBinding result = null;

			uint retVal;
			HttpApi.CallHttpApi(
				delegate {
					GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(ipPort);
					IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();
					var sslKey = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);

					var inputConfigInfoQuery = new HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY {
						QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
						KeyDesc = sslKey
					};

					IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
						Marshal.SizeOf(typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY)));
					Marshal.StructureToPtr(inputConfigInfoQuery, pInputConfigInfo, false);

					IntPtr pOutputConfigInfo = IntPtr.Zero;
					int returnLength = 0;

					try {
						int inputConfigInfoSize = Marshal.SizeOf(inputConfigInfoQuery);
						retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
							HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
							pInputConfigInfo,
							inputConfigInfoSize,
							pOutputConfigInfo,
							returnLength,
							out returnLength,
							IntPtr.Zero);
						if (retVal == HttpApi.ERROR_FILE_NOT_FOUND)
							return;

						if (HttpApi.ERROR_INSUFFICIENT_BUFFER == retVal) {
							pOutputConfigInfo = Marshal.AllocCoTaskMem(returnLength);
							try {
								retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
									HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
									pInputConfigInfo,
									inputConfigInfoSize,
									pOutputConfigInfo,
									returnLength,
									out returnLength,
									IntPtr.Zero);
								HttpApi.ThrowWin32ExceptionIfError(retVal);

								var outputConfigInfo =
									(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET)
									Marshal.PtrToStructure(pOutputConfigInfo, typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET));
								result = CreateCertificateBindingInfo(outputConfigInfo);
							} finally {
								Marshal.FreeCoTaskMem(pOutputConfigInfo);
							}
						} else {
							HttpApi.ThrowWin32ExceptionIfError(retVal);
						}

					} finally {
						Marshal.FreeCoTaskMem(pInputConfigInfo);
						if (sockAddrHandle.IsAllocated)
							sockAddrHandle.Free();
					}
				});

			return result;
		}

		private static CertificateBinding[] QueryInternal() {
			var result = new List<CertificateBinding>();

			HttpApi.CallHttpApi(
				delegate {
					uint token = 0;

					uint retVal;
					do {
						var inputConfigInfoQuery = new HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY {
								QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
								dwToken = token,
							};

						IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
							Marshal.SizeOf(typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY)));
						Marshal.StructureToPtr(inputConfigInfoQuery, pInputConfigInfo, false);

						IntPtr pOutputConfigInfo = IntPtr.Zero;
						int returnLength = 0;

						try {
							int inputConfigInfoSize = Marshal.SizeOf(inputConfigInfoQuery);
							retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
								HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
								pInputConfigInfo,
								inputConfigInfoSize,
								pOutputConfigInfo,
								returnLength,
								out returnLength,
								IntPtr.Zero);
							if (HttpApi.ERROR_NO_MORE_ITEMS == retVal)
								break;
							if (HttpApi.ERROR_INSUFFICIENT_BUFFER == retVal) {
								pOutputConfigInfo = Marshal.AllocCoTaskMem(returnLength);

								try {
									retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
										HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
										pInputConfigInfo,
										inputConfigInfoSize,
										pOutputConfigInfo,
										returnLength,
										out returnLength,
										IntPtr.Zero);
									HttpApi.ThrowWin32ExceptionIfError(retVal);

									var outputConfigInfo = (HttpApi.HTTP_SERVICE_CONFIG_SSL_SET)Marshal.PtrToStructure(
										pOutputConfigInfo, typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET));
									var resultItem = CreateCertificateBindingInfo(outputConfigInfo);
									result.Add(resultItem);
									token++;
								} finally {
									Marshal.FreeCoTaskMem(pOutputConfigInfo);
								}
							} else {
								HttpApi.ThrowWin32ExceptionIfError(retVal);
							}
						} finally {
							Marshal.FreeCoTaskMem(pInputConfigInfo);
						}

					} while (HttpApi.NOERROR == retVal);

				});

			return result.ToArray();
		}

		private static CertificateBinding CreateCertificateBindingInfo(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET configInfo) {
			byte[] hash = new byte[configInfo.ParamDesc.SslHashLength];
			Marshal.Copy(configInfo.ParamDesc.pSslHash, hash, 0, hash.Length);
			Guid appId = configInfo.ParamDesc.AppId;
			string storeName = configInfo.ParamDesc.pSslCertStoreName;
			IPEndPoint ipPort = SockaddrInterop.ReadSockaddrStructure(configInfo.KeyDesc.pIpPort);
			var checkModes = configInfo.ParamDesc.DefaultCertCheckMode;
			var options = new BindingOptions {
				DoNotVerifyCertificateRevocation = HasFlag(checkModes, HttpApi.CertCheckModes.DoNotVerifyCertificateRevocation),
				VerifyRevocationWithCachedCertificateOnly = HasFlag(checkModes, HttpApi.CertCheckModes.VerifyRevocationWithCachedCertificateOnly),
				EnableRevocationFreshnessTime = HasFlag(checkModes, HttpApi.CertCheckModes.EnableRevocationFreshnessTime),
				NoUsageCheck = HasFlag(checkModes, HttpApi.CertCheckModes.NoUsageCheck),
				RevocationFreshnessTime = TimeSpan.FromSeconds(configInfo.ParamDesc.DefaultRevocationFreshnessTime),
				RevocationUrlRetrievalTimeout = TimeSpan.FromMilliseconds(configInfo.ParamDesc.DefaultRevocationUrlRetrievalTimeout),
				SslCtlIdentifier = configInfo.ParamDesc.pDefaultSslCtlIdentifier,
				SslCtlStoreName = configInfo.ParamDesc.pDefaultSslCtlStoreName,
				NegotiateCertificate = HasFlag(configInfo.ParamDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NEGOTIATE_CLIENT_CERT),
				UseDsMappers = HasFlag(configInfo.ParamDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.USE_DS_MAPPER),
				DoNotPassRequestsToRawFilters = HasFlag(configInfo.ParamDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NO_RAW_FILTER),
			};
			var result = new CertificateBinding(GetThumbrint(hash), storeName, ipPort, appId, options);
			return result;
		}

		private static string GetThumbrint(byte[] hash) {
			string thumbrint = BitConverter.ToString(hash).Replace("-", "");
			return thumbrint;
		}

		private static byte[] GetHash(string thumbprint) {
			int length = thumbprint.Length;
			byte[] bytes = new byte[length / 2];
			for (int i = 0; i < length; i += 2)
				bytes[i / 2] = Convert.ToByte(thumbprint.Substring(i, 2), 16);
			return bytes;
		}

		private static bool HasFlag(uint value, uint flag) {
			return (value & flag) == flag;
		}

		private static bool HasFlag<T>(T value, T flag) where T : IConvertible {
			var uintValue = Convert.ToUInt32(value);
			var uintFlag = Convert.ToUInt32(flag);
			return HasFlag(uintValue, uintFlag);
		}
	}
}
