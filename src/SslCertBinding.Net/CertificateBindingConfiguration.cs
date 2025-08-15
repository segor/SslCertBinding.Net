using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;

namespace SslCertBinding.Net
{
    
    /// <summary>
    /// Provides methods to manage SSL certificate bindings.
    /// </summary>
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public class CertificateBindingConfiguration : ICertificateBindingConfiguration
    {

        private delegate CertificateBinding MapBinding<in TBindingStruct>(TBindingStruct output);

        /// <summary>
        /// Queries the SSL certificate bindings for the specified endpoint.
        /// </summary>
        /// <param name="endPoint">The endpoint to query. If <c>null</c>, all bindings are returned.</param>
        /// <returns>A list of <see cref="CertificateBinding"/> objects.</returns>
        public IReadOnlyList<CertificateBinding> Query(BindingEndPoint endPoint = null)
        {
            if (endPoint == null)
                return QueryMany();

            CertificateBinding info = endPoint.IsIpEndpoint
                ? QuerySingle(endPoint.ToIPEndPoint())
                : QuerySingle(endPoint.ToDnsEndPoint());
            return info == null ? Array.Empty<CertificateBinding>() : new[] { info };
        }

        /// <summary>
        /// Binds an SSL certificate to an endpoint.
        /// </summary>
        /// <param name="binding">The <see cref="CertificateBinding"/> object containing the binding information.</param> 
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="binding"/> is null.</exception>
        /// <exception cref="Win32Exception">Thrown when an Win32 error occurred.</exception>
        public void Bind(CertificateBinding binding)
        {
            _ = binding.ThrowIfNull(nameof(binding));
            
            HttpApi.CallHttpApi(
                delegate
                {
                    GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(binding.EndPoint.ToIPEndPoint());
                    IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();
                    var httpServiceConfigSslKey = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);

                    byte[] hash = GetHash(binding.Thumbprint);
                    GCHandle handleHash = GCHandle.Alloc(hash, GCHandleType.Pinned);
                    BindingOptions options = binding.Options;
                    var configSslParam = new HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM
                    {
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

                    var configSslSet = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SET
                    {
                        ParamDesc = configSslParam,
                        KeyDesc = httpServiceConfigSslKey
                    };

                    IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
                        Marshal.SizeOf(typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET)));
                    Marshal.StructureToPtr(configSslSet, pInputConfigInfo, false);

                    try
                    {
                        uint retVal = HttpApi.HttpSetServiceConfiguration(IntPtr.Zero,
                            HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                            pInputConfigInfo,
                            Marshal.SizeOf(configSslSet),
                            IntPtr.Zero);

                        if (HttpApi.ERROR_ALREADY_EXISTS != retVal)
                        {
                            HttpApi.ThrowWin32ExceptionIfError(retVal);
                        }
                        else
                        {
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
                    }
                    finally
                    {
                        Marshal.FreeCoTaskMem(pInputConfigInfo);
                        if (handleHash.IsAllocated)
                            handleHash.Free();
                        if (sockAddrHandle.IsAllocated)
                            sockAddrHandle.Free();
                    }
                });
        }

        /// <summary>
        /// Deletes an SSL certificate binding for the specified endpoint.
        /// </summary>
        /// <param name="endPoint">The endpoint to delete the binding for.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="endPoint"/> is null.</exception>
        /// <exception cref="Win32Exception">Thrown when an Win32 error occurred.</exception>
        public void Delete(BindingEndPoint endPoint)
        {
            if (endPoint is null)
            {
                throw new ArgumentNullException(nameof(endPoint));
            }

            Delete(new[] { endPoint });
        }

        /// <summary>
        /// Deletes SSL certificate bindings for the specified endpoints.
        /// </summary>
        /// <param name="endPoints">The collection of endpoints to delete the bindings for.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="endPoints"/> is null.</exception>
        /// <exception cref="Win32Exception">Thrown when an Win32 error occurred.</exception>
        public void Delete(IReadOnlyCollection<BindingEndPoint> endPoints)
        {
            _ = endPoints .ThrowIfNull(nameof(endPoints));
            if (endPoints.Count == 0)
                return;

            HttpApi.CallHttpApi(
            delegate
            {
                foreach (BindingEndPoint endPoint in endPoints)
                {
                    IPEndPoint ipPort = endPoint.ToIPEndPoint();
                    GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(ipPort);
                    IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();
                    var httpServiceConfigSslKey = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);

                    var configSslSet = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SET
                    {
                        KeyDesc = httpServiceConfigSslKey
                    };

                    IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
                            Marshal.SizeOf(typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET)));
                    Marshal.StructureToPtr(configSslSet, pInputConfigInfo, false);

                    try
                    {
                        uint retVal = HttpApi.HttpDeleteServiceConfiguration(IntPtr.Zero,
                            HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                            pInputConfigInfo,
                            Marshal.SizeOf(configSslSet),
                            IntPtr.Zero);
                        HttpApi.ThrowWin32ExceptionIfError(retVal);
                    }
                    finally
                    {
                        Marshal.FreeCoTaskMem(pInputConfigInfo);
                        if (sockAddrHandle.IsAllocated)
                            sockAddrHandle.Free();
                    }
                }
            });
        }

       
        private static CertificateBinding QuerySingle<TQueryStruct, TBindingStruct>(HttpApi.HTTP_SERVICE_CONFIG_ID configId,
            TQueryStruct queryStruct, MapBinding<TBindingStruct> mapFunc)
        {
            CertificateBinding result = null;

            uint retVal;
            HttpApi.CallHttpApi(
                delegate
                {

                    IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
                        Marshal.SizeOf(queryStruct.GetType()));
                    Marshal.StructureToPtr(queryStruct, pInputConfigInfo, false);

                    IntPtr pOutputConfigInfo = IntPtr.Zero;
                    int returnLength = 0;

                    try
                    {
                        int inputConfigInfoSize = Marshal.SizeOf(queryStruct);
                        retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
                            configId,
                            pInputConfigInfo,
                            inputConfigInfoSize,
                            pOutputConfigInfo,
                            returnLength,
                            out returnLength,
                            IntPtr.Zero);
                        if (retVal == HttpApi.ERROR_FILE_NOT_FOUND)
                            return;

                        if (HttpApi.ERROR_INSUFFICIENT_BUFFER == retVal)
                        {
                            pOutputConfigInfo = Marshal.AllocCoTaskMem(returnLength);
                            try
                            {
                                retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
                                    configId,
                                    pInputConfigInfo,
                                    inputConfigInfoSize,
                                    pOutputConfigInfo,
                                    returnLength,
                                    out returnLength,
                                    IntPtr.Zero);
                                HttpApi.ThrowWin32ExceptionIfError(retVal);

                                var outputConfigInfo = (TBindingStruct)Marshal.PtrToStructure(
                                    pOutputConfigInfo, typeof(TBindingStruct));
                                result = mapFunc(outputConfigInfo);
                            }
                            finally
                            {
                                Marshal.FreeCoTaskMem(pOutputConfigInfo);
                            }
                        }
                        else
                        {
                            HttpApi.ThrowWin32ExceptionIfError(retVal);
                        }

                    }
                    finally
                    {
                        Marshal.FreeCoTaskMem(pInputConfigInfo);
                    }
                });

            return result;
        }

        private static CertificateBinding QuerySingle(IPEndPoint ipPort)
        {
            GCHandle sockAddrHandle = SockaddrInterop.CreateSockaddrStructure(ipPort);
            IntPtr pIpPort = sockAddrHandle.AddrOfPinnedObject();
            var sslKey = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(pIpPort);

            var queryStruct = new HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY
            {
                QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
                KeyDesc = sslKey
            };

            try
            {
                return QuerySingle(
                    HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                    queryStruct,
                    (MapBinding<HttpApi.HTTP_SERVICE_CONFIG_SSL_SET>)CertificateBindingMapper.CreateCertificateBindingInfo);
            }
            finally
            {
                if (sockAddrHandle.IsAllocated)
                    sockAddrHandle.Free();
            }
        }

        private static CertificateBinding QuerySingle(DnsEndPoint hostnamePort)
        {
            var sockAddrStorage = SockaddrInterop.CreateSockaddrStorage(hostnamePort.Port);
            var queryStruct = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY
            {
                QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
                KeyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_KEY { IpPort = sockAddrStorage, Host = hostnamePort.Host }
            };

            return QuerySingle(
                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo,
                queryStruct,
                (MapBinding<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET>)CertificateBindingMapper.CreateCertificateBindingInfo);
        }

        private static List<CertificateBinding> QueryMany()
        {
            var result = new List<CertificateBinding>();

            HttpApi.CallHttpApi(
                delegate
                {
                    uint token = 0;

                    uint retVal;
                    do
                    {
                        var inputConfigInfoQuery = new HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY
                        {
                            QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
                            dwToken = token,
                        };

                        IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(
                            Marshal.SizeOf(typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY)));
                        Marshal.StructureToPtr(inputConfigInfoQuery, pInputConfigInfo, false);

                        IntPtr pOutputConfigInfo = IntPtr.Zero;
                        int returnLength = 0;

                        try
                        {
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
                            if (HttpApi.ERROR_INSUFFICIENT_BUFFER == retVal)
                            {
                                pOutputConfigInfo = Marshal.AllocCoTaskMem(returnLength);

                                try
                                {
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
                                    CertificateBinding resultItem = CertificateBindingMapper.CreateCertificateBindingInfo(outputConfigInfo);
                                    result.Add(resultItem);
                                    token++;
                                }
                                finally
                                {
                                    Marshal.FreeCoTaskMem(pOutputConfigInfo);
                                }
                            }
                            else
                            {
                                HttpApi.ThrowWin32ExceptionIfError(retVal);
                            }
                        }
                        finally
                        {
                            Marshal.FreeCoTaskMem(pInputConfigInfo);
                        }

                    } while (HttpApi.NOERROR == retVal);

                });

            return result;
        }

        private static byte[] GetHash(string thumbprint)
        {
            int length = thumbprint.Length;
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
                bytes[i / 2] = Convert.ToByte(thumbprint.Substring(i, 2), 16);
            return bytes;
        }
    }
}
