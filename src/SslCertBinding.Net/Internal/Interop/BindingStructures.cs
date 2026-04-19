using System;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;

namespace SslCertBinding.Net.Internal.Interop
{
    internal static class BindingStructures
    {
        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_SET> CreateSetStruct(IpPortBinding binding)
        {
            IntPtr ipPortPtr = SockaddrInterop.CreateSockaddrStructPtr(binding.Key.ToIPEndPoint(), out Action freeSockaddr);
            HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM paramDesc = CreateConfigSslParam(binding.Certificate, binding.AppId, binding.Options, out Action freeParam);

            return new(
                new()
                {
                    KeyDesc = new(ipPortPtr),
                    ParamDesc = paramDesc,
                },
                freeParam,
                freeSockaddr);
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET> CreateSetStruct(HostnamePortBinding binding)
        {
            HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM paramDesc = CreateConfigSslParam(binding.Certificate, binding.AppId, binding.Options, out Action freeParam);

            return new(
                new()
                {
                    KeyDesc = new()
                    {
                        Host = binding.Key.Hostname,
                        IpPort = SockaddrInterop.CreateSockaddrStorage(binding.Key.Port),
                    },
                    ParamDesc = paramDesc,
                },
                freeParam);
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_SET> CreateSetStruct(CcsPortBinding binding)
        {
            HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM paramDesc = CreateConfigSslParam(binding.AppId, binding.Options);

            return new(
                new()
                {
                    KeyDesc = new()
                    {
                        LocalAddress = SockaddrInterop.CreateCcsWildcardSockaddrStorage(binding.Key.Port),
                    },
                    ParamDesc = paramDesc,
                });
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET> CreateSetStruct(ScopedCcsBinding binding)
        {
            HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM paramDesc = CreateConfigSslParam(binding.AppId, binding.Options);

            return new(
                new()
                {
                    KeyDesc = new()
                    {
                        Host = binding.Key.Hostname,
                        IpPort = SockaddrInterop.CreateSockaddrStorage(binding.Key.Port),
                    },
                    ParamDesc = paramDesc,
                });
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_SET> CreateDeleteStruct(IpPortKey key)
        {
            IntPtr ipPortPtr = SockaddrInterop.CreateSockaddrStructPtr(key.ToIPEndPoint(), out Action freeSockaddr);
            return new(
                new()
                {
                    KeyDesc = new(ipPortPtr),
                },
                freeSockaddr);
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET> CreateDeleteStruct(HostnamePortKey key)
        {
            return new(
                new()
                {
                    KeyDesc = new()
                    {
                        Host = key.Hostname,
                        IpPort = SockaddrInterop.CreateSockaddrStorage(key.Port),
                    },
                });
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_SET> CreateDeleteStruct(CcsPortKey key)
        {
            return new(
                new()
                {
                    KeyDesc = new()
                    {
                        LocalAddress = SockaddrInterop.CreateCcsWildcardSockaddrStorage(key.Port),
                    },
                });
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET> CreateDeleteStruct(ScopedCcsKey key)
        {
            return new(
                new()
                {
                    KeyDesc = new()
                    {
                        Host = key.Hostname,
                        IpPort = SockaddrInterop.CreateSockaddrStorage(key.Port),
                    },
                });
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY> CreateExactQuery(IpPortKey key)
        {
            IntPtr ipPortPtr = SockaddrInterop.CreateSockaddrStructPtr(key.ToIPEndPoint(), out Action freeSockaddr);
            return new(
                new()
                {
                    QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
                    KeyDesc = new(ipPortPtr),
                },
                freeSockaddr);
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY> CreateExactQuery(HostnamePortKey key)
        {
            return new(
                new()
                {
                    QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
                    KeyDesc = new()
                    {
                        Host = key.Hostname,
                        IpPort = SockaddrInterop.CreateSockaddrStorage(key.Port),
                    },
                });
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_QUERY> CreateExactQuery(CcsPortKey key)
        {
            return new(
                new()
                {
                    QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
                    KeyDesc = new()
                    {
                        LocalAddress = SockaddrInterop.CreateCcsWildcardSockaddrStorage(key.Port),
                    },
                });
        }

        public static SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY> CreateExactQuery(ScopedCcsKey key)
        {
            return new(
                new()
                {
                    QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
                    KeyDesc = new()
                    {
                        Host = key.Hostname,
                        IpPort = SockaddrInterop.CreateSockaddrStorage(key.Port),
                    },
                });
        }

        public static HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY CreateNextIpQuery(uint token) => new()
        {
            QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
            dwToken = token,
        };

        public static HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY CreateNextHostnameQuery(uint token) => new()
        {
            QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
            dwToken = token,
        };

        public static HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_QUERY CreateNextCcsQuery(uint token) => new()
        {
            QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
            dwToken = token,
        };

        public static HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY CreateNextScopedCcsQuery(uint token) => new()
        {
            QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
            dwToken = token,
        };

        public static IpPortBinding MapIpBinding(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET bindingStruct)
        {
            byte[] hashBytes = new byte[bindingStruct.ParamDesc.SslHashLength];
            Marshal.Copy(bindingStruct.ParamDesc.pSslHash, hashBytes, 0, hashBytes.Length);

            return new(
                new(SockaddrInterop.ReadSockaddrStructPtr(bindingStruct.KeyDesc.pIpPort)),
                new(GetThumbprint(hashBytes), bindingStruct.ParamDesc.pSslCertStoreName),
                bindingStruct.ParamDesc.AppId,
                CreateBindingOptions(bindingStruct.ParamDesc));
        }

        public static HostnamePortBinding MapHostnameBinding(HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET bindingStruct)
        {
            byte[] hashBytes = new byte[bindingStruct.ParamDesc.SslHashLength];
            Marshal.Copy(bindingStruct.ParamDesc.pSslHash, hashBytes, 0, hashBytes.Length);

            IPEndPoint ipPort = SockaddrInterop.CreateIPEndPoint(bindingStruct.KeyDesc.IpPort);
            return new(
                new(bindingStruct.KeyDesc.Host, ipPort.Port),
                new(GetThumbprint(hashBytes), bindingStruct.ParamDesc.pSslCertStoreName),
                bindingStruct.ParamDesc.AppId,
                CreateBindingOptions(bindingStruct.ParamDesc));
        }

        public static CcsPortBinding MapCcsBinding(HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_SET bindingStruct)
        {
            IPEndPoint localAddress = SockaddrInterop.CreateIPEndPoint(bindingStruct.KeyDesc.LocalAddress);
            return new(
                new(localAddress.Port),
                bindingStruct.ParamDesc.AppId,
                CreateBindingOptions(bindingStruct.ParamDesc));
        }

        public static ScopedCcsBinding MapScopedCcsBinding(HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET bindingStruct)
        {
            IPEndPoint ipPort = SockaddrInterop.CreateIPEndPoint(bindingStruct.KeyDesc.IpPort);
            return new(
                new(bindingStruct.KeyDesc.Host, ipPort.Port),
                bindingStruct.ParamDesc.AppId,
                CreateBindingOptions(bindingStruct.ParamDesc));
        }

        private static HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM CreateConfigSslParam(
            SslCertificateReference certificate,
            Guid appId,
            BindingOptions options,
            out Action freeResources)
        {
            byte[] hashBytes = GetHashBytes(certificate.Thumbprint);
            GCHandle hashHandle = GCHandle.Alloc(hashBytes, GCHandleType.Pinned);

            freeResources = () =>
            {
                if (hashHandle.IsAllocated)
                {
                    hashHandle.Free();
                }
            };

            return new()
            {
                AppId = appId,
                DefaultCertCheckMode =
                    (options.DoNotVerifyCertificateRevocation ? HttpApi.CertCheckModes.DoNotVerifyCertificateRevocation : 0)
                    | (options.VerifyRevocationWithCachedCertificateOnly ? HttpApi.CertCheckModes.VerifyRevocationWithCachedCertificateOnly : 0)
                    | (options.EnableRevocationFreshnessTime ? HttpApi.CertCheckModes.EnableRevocationFreshnessTime : 0)
                    | (options.NoUsageCheck ? HttpApi.CertCheckModes.NoUsageCheck : 0),
                DefaultFlags =
                    (options.NegotiateCertificate ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NEGOTIATE_CLIENT_CERT : 0)
                    | (options.UseDsMappers ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.USE_DS_MAPPER : 0)
                    | (options.DoNotPassRequestsToRawFilters ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NO_RAW_FILTER : 0)
                    | (options.DisableTls12 ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.DISABLE_TLS_1_2 : 0),
                DefaultRevocationFreshnessTime = (int)options.RevocationFreshnessTime.TotalSeconds,
                DefaultRevocationUrlRetrievalTimeout = (int)options.RevocationUrlRetrievalTimeout.TotalMilliseconds,
                pSslCertStoreName = certificate.StoreName,
                pSslHash = hashHandle.AddrOfPinnedObject(),
                SslHashLength = hashBytes.Length,
                pDefaultSslCtlIdentifier = options.SslCtlIdentifier,
                pDefaultSslCtlStoreName = options.SslCtlStoreName,
            };
        }

        private static HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM CreateConfigSslParam(
            Guid appId,
            BindingOptions options)
        {
            return new()
            {
                AppId = appId,
                DefaultCertCheckMode =
                    (options.DoNotVerifyCertificateRevocation ? HttpApi.CertCheckModes.DoNotVerifyCertificateRevocation : 0)
                    | (options.VerifyRevocationWithCachedCertificateOnly ? HttpApi.CertCheckModes.VerifyRevocationWithCachedCertificateOnly : 0)
                    | (options.EnableRevocationFreshnessTime ? HttpApi.CertCheckModes.EnableRevocationFreshnessTime : 0)
                    | (options.NoUsageCheck ? HttpApi.CertCheckModes.NoUsageCheck : 0),
                DefaultFlags =
                    (options.NegotiateCertificate ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NEGOTIATE_CLIENT_CERT : 0)
                    | (options.UseDsMappers ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.USE_DS_MAPPER : 0)
                    | (options.DoNotPassRequestsToRawFilters ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NO_RAW_FILTER : 0)
                    | (options.DisableTls12 ? HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.DISABLE_TLS_1_2 : 0),
                DefaultRevocationFreshnessTime = (int)options.RevocationFreshnessTime.TotalSeconds,
                DefaultRevocationUrlRetrievalTimeout = (int)options.RevocationUrlRetrievalTimeout.TotalMilliseconds,
                pDefaultSslCtlIdentifier = options.SslCtlIdentifier,
                pDefaultSslCtlStoreName = options.SslCtlStoreName,
            };
        }

        private static BindingOptions CreateBindingOptions(HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM paramDesc) => new()
        {
            DoNotVerifyCertificateRevocation = HasFlag(paramDesc.DefaultCertCheckMode, HttpApi.CertCheckModes.DoNotVerifyCertificateRevocation),
            VerifyRevocationWithCachedCertificateOnly = HasFlag(paramDesc.DefaultCertCheckMode, HttpApi.CertCheckModes.VerifyRevocationWithCachedCertificateOnly),
            EnableRevocationFreshnessTime = HasFlag(paramDesc.DefaultCertCheckMode, HttpApi.CertCheckModes.EnableRevocationFreshnessTime),
            NoUsageCheck = HasFlag(paramDesc.DefaultCertCheckMode, HttpApi.CertCheckModes.NoUsageCheck),
            RevocationFreshnessTime = TimeSpan.FromSeconds(paramDesc.DefaultRevocationFreshnessTime),
            RevocationUrlRetrievalTimeout = TimeSpan.FromMilliseconds(paramDesc.DefaultRevocationUrlRetrievalTimeout),
            SslCtlIdentifier = paramDesc.pDefaultSslCtlIdentifier,
            SslCtlStoreName = paramDesc.pDefaultSslCtlStoreName,
            NegotiateCertificate = HasFlag(paramDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NEGOTIATE_CLIENT_CERT),
            UseDsMappers = HasFlag(paramDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.USE_DS_MAPPER),
            DoNotPassRequestsToRawFilters = HasFlag(paramDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NO_RAW_FILTER),
            DisableTls12 = HasFlag(paramDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.DISABLE_TLS_1_2),
        };

        private static byte[] GetHashBytes(string thumbprint)
        {
            byte[] bytes = new byte[thumbprint.Length / 2];
            for (int index = 0; index < thumbprint.Length; index += 2)
            {
                bytes[index / 2] = Convert.ToByte(thumbprint.Substring(index, 2), 16);
            }

            return bytes;
        }

        private static string GetThumbprint(byte[] hash)
        {
#if NET5_0_OR_GREATER
            return Convert.ToHexString(hash);
#else
            return BitConverter.ToString(hash).Replace("-", string.Empty);
#endif
        }

        private static bool HasFlag<T>(T value, T flag)
            where T : IConvertible
        {
            uint uintValue = Convert.ToUInt32(value, CultureInfo.InvariantCulture);
            uint uintFlag = Convert.ToUInt32(flag, CultureInfo.InvariantCulture);
            return (uintValue & uintFlag) == uintFlag;
        }
    }
}
