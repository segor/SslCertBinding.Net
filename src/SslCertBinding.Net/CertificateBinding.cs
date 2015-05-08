using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace SslCertBinding.Net
{
	public class CertificateBinding : ICertificateBinding
	{
		public CertificateBindingInfo QueryBinding(IPEndPoint ipPort) {
			CertificateBindingInfo result = null;

			uint retVal;
			HttpApi.CallHttpApi(
				delegate {
					GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(ipPort);
					IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();
					HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY sslKey = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);

					HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY inputConfigInfoQuery =
						new HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY {
							QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
							KeyDesc = sslKey
						};

					IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
						Marshal.SizeOf(typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY)));
					Marshal.StructureToPtr(inputConfigInfoQuery, pInputConfigInfo, false);

					IntPtr pOutputConfigInfo = IntPtr.Zero;
					int returnLength = 0;

					try {
						HttpApi.HTTP_SERVICE_CONFIG_ID queryType = HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo;
						int inputConfigInfoSize = Marshal.SizeOf(inputConfigInfoQuery);
						retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero, 
							queryType, 
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
									queryType,
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

								byte[] hash = new byte[outputConfigInfo.ParamDesc.SslHashLength];
								Marshal.Copy(outputConfigInfo.ParamDesc.pSslHash, hash, 0, hash.Length);

								Guid appId = outputConfigInfo.ParamDesc.AppId;
								string storeName = outputConfigInfo.ParamDesc.pSslCertStoreName;

								result = new CertificateBindingInfo(GetThumbrint(hash), storeName, ipPort, appId);
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

		public void Bind(CertificateBindingInfo binding) {
			HttpApi.CallHttpApi(
				delegate {
					HttpApi.HTTP_SERVICE_CONFIG_SSL_SET configSslSet = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SET();

					GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(binding.IpPort);
					IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();
					HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY httpServiceConfigSslKey = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);
					HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM configSslParam = new HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM();

					byte[] hash = GetHash(binding.Thumbprint);
					GCHandle handleHash = GCHandle.Alloc(hash, GCHandleType.Pinned);
					configSslParam.AppId = binding.AppId;
					configSslParam.DefaultCertCheckMode = 0;
					configSslParam.DefaultFlags = 0; 
					configSslParam.DefaultRevocationFreshnessTime = 0;
					configSslParam.DefaultRevocationUrlRetrievalTimeout = 0;
					configSslParam.pSslCertStoreName = binding.StoreName;
					configSslParam.pSslHash = handleHash.AddrOfPinnedObject();
					configSslParam.SslHashLength = hash.Length;
					configSslSet.ParamDesc = configSslParam;
					configSslSet.KeyDesc = httpServiceConfigSslKey;

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
						}
					} finally {
						Marshal.FreeCoTaskMem(pInputConfigInfo);
						if (handleHash.IsAllocated)
							handleHash.Free();
						if (sockAddrHandle.IsAllocated)
							sockAddrHandle.Free();
					}
				});
		}

		public void DeleteBinding(IPEndPoint endPoint) {
			DeleteBinding(new[] {endPoint});
		}

		public void DeleteBinding(IPEndPoint[] endPoints) {
			if (endPoints == null) throw new ArgumentNullException("endPoints");
			if (endPoints.Length == 0)
				return;

			HttpApi.CallHttpApi(
			delegate {
				foreach (var ipPort in endPoints) {
					HttpApi.HTTP_SERVICE_CONFIG_SSL_SET configSslSet =
						new HttpApi.HTTP_SERVICE_CONFIG_SSL_SET();

					GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(ipPort);
					IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();
					HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY httpServiceConfigSslKey = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);
					configSslSet.KeyDesc = httpServiceConfigSslKey;

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

		public CertificateBindingInfo[] QueryBinding() {
			var result = new List<CertificateBindingInfo>();

			HttpApi.CallHttpApi(
				delegate {
					uint token = 0;

					uint retVal;
					do {
						HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY inputConfigInfoQuery =
							new HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY {
								QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
								dwToken = token,
							};

						IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
							Marshal.SizeOf(typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY)));
						Marshal.StructureToPtr(inputConfigInfoQuery, pInputConfigInfo, false);

						IntPtr pOutputConfigInfo = IntPtr.Zero;
						int returnLength = 0;

						const HttpApi.HTTP_SERVICE_CONFIG_ID queryType = HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo;

						try {
							int inputConfigInfoSize = Marshal.SizeOf(inputConfigInfoQuery);
							retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
								queryType,
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
										queryType,
										pInputConfigInfo,
										inputConfigInfoSize,
										pOutputConfigInfo,
										returnLength,
										out returnLength,
										IntPtr.Zero);
									HttpApi.ThrowWin32ExceptionIfError(retVal);

									var outputConfigInfo = (HttpApi.HTTP_SERVICE_CONFIG_SSL_SET)Marshal.PtrToStructure(
										pOutputConfigInfo, typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET));

									byte[] hash = new byte[outputConfigInfo.ParamDesc.SslHashLength];
									Marshal.Copy(outputConfigInfo.ParamDesc.pSslHash, hash, 0, hash.Length);

									Guid appId = outputConfigInfo.ParamDesc.AppId;
									string storeName = outputConfigInfo.ParamDesc.pSslCertStoreName;

									IPEndPoint ipPort = SockaddrInterop.ReadSockaddrStructure(outputConfigInfo.KeyDesc.pIpPort);

									var resultItem = new CertificateBindingInfo(GetThumbrint(hash), storeName, ipPort, appId);
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
	}
}
