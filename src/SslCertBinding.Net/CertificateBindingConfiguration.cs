using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using SslCertBinding.Net.Interop;

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
            {
                var list = QueryManyIpEndpoints();
                list.AddRange(QueryManyDnsEndpoints());
                return list;
            }

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
                    HttpApi.HTTP_SERVICE_CONFIG_SSL_SET bindingStruct = BindingStructures.CreateBindingStruct(binding, out Action freeResources);
                    IntPtr bindingStructPtr = StructureToPtr(bindingStruct);

                    try
                    {
                        uint retVal = HttpApi.HttpSetServiceConfiguration(IntPtr.Zero,
                            HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                            bindingStructPtr,
                            Marshal.SizeOf(bindingStruct),
                            IntPtr.Zero);

                        if (HttpApi.ERROR_ALREADY_EXISTS != retVal)
                        {
                            HttpApi.ThrowWin32ExceptionIfError(retVal);
                        }
                        else
                        {
                            retVal = HttpApi.HttpDeleteServiceConfiguration(IntPtr.Zero,
                                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                                bindingStructPtr,
                                Marshal.SizeOf(bindingStruct),
                                IntPtr.Zero);
                            HttpApi.ThrowWin32ExceptionIfError(retVal);

                            retVal = HttpApi.HttpSetServiceConfiguration(IntPtr.Zero,
                                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                                bindingStructPtr,
                                Marshal.SizeOf(bindingStruct),
                                IntPtr.Zero);
                            HttpApi.ThrowWin32ExceptionIfError(retVal);
                        }
                    }
                    finally
                    {
                        Marshal.FreeCoTaskMem(bindingStructPtr);
                        freeResources();
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
                    HttpApi.HTTP_SERVICE_CONFIG_SSL_SET bindingStruct = BindingStructures.CreateBindingStruct(endPoint, out Action freeResources);
                    IntPtr bindingStructPtr = StructureToPtr(bindingStruct);

                    try
                    {
                        uint retVal = HttpApi.HttpDeleteServiceConfiguration(IntPtr.Zero,
                            HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                            bindingStructPtr,
                            Marshal.SizeOf(bindingStruct),
                            IntPtr.Zero);
                        HttpApi.ThrowWin32ExceptionIfError(retVal);
                    }
                    finally
                    {
                        Marshal.FreeCoTaskMem(bindingStructPtr);
                        freeResources();
                    }
                }
            });
        }

       
        private static CertificateBinding QuerySingle<TQueryStruct, TBindingStruct>(HttpApi.HTTP_SERVICE_CONFIG_ID configId,
            TQueryStruct queryStruct, MapBinding<TBindingStruct> mapFunc) where TQueryStruct : struct where TBindingStruct : struct
        {
            CertificateBinding result = null;

            uint retVal;
            HttpApi.CallHttpApi(
                delegate
                {
                    IntPtr queryStructPtr = StructureToPtr(queryStruct);
                    IntPtr bindingStructPtr = IntPtr.Zero;
                    int returnLength = 0;

                    try
                    {
                        int pQueryStructSize = Marshal.SizeOf(queryStruct);
                        retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
                            configId,
                            queryStructPtr,
                            pQueryStructSize,
                            bindingStructPtr,
                            returnLength,
                            out returnLength,
                            IntPtr.Zero);
                        if (retVal == HttpApi.ERROR_FILE_NOT_FOUND)
                            return;

                        if (HttpApi.ERROR_INSUFFICIENT_BUFFER == retVal)
                        {
                            bindingStructPtr = Marshal.AllocCoTaskMem(returnLength);
                            try
                            {
                                retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
                                    configId,
                                    queryStructPtr,
                                    pQueryStructSize,
                                    bindingStructPtr,
                                    returnLength,
                                    out returnLength,
                                    IntPtr.Zero);
                                HttpApi.ThrowWin32ExceptionIfError(retVal);

                                var bindingStruct = (TBindingStruct)Marshal.PtrToStructure(bindingStructPtr, typeof(TBindingStruct));
                                result = mapFunc(bindingStruct);
                            }
                            finally
                            {
                                Marshal.FreeCoTaskMem(bindingStructPtr);
                            }
                        }
                        else
                        {
                            HttpApi.ThrowWin32ExceptionIfError(retVal);
                        }

                    }
                    finally
                    {
                        Marshal.FreeCoTaskMem(queryStructPtr);
                    }
                });

            return result;
        }

        private static CertificateBinding QuerySingle(IPEndPoint ipPort)
        {
            IntPtr ipPortPtr = SockaddrStructure.CreateSockaddrStructPtr(ipPort, out Action freeResources);
            try
            {
                var queryStruct = new HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY
                {
                    QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
                    KeyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(ipPortPtr)
                };
                return QuerySingle(
                    HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                    queryStruct,
                    (MapBinding<HttpApi.HTTP_SERVICE_CONFIG_SSL_SET>)BindingStructures.CreateBinding);
            }
            finally
            {
                freeResources();
            }
        }

        private static CertificateBinding QuerySingle(DnsEndPoint hostnamePort)
        {
            var sockAddrStorage = SockaddrStructure.CreateSockaddrStorage(hostnamePort.Port);
            var queryStruct = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY
            {
                QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryExact,
                KeyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_KEY { IpPort = sockAddrStorage, Host = hostnamePort.Host }
            };

            return QuerySingle(
                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo,
                queryStruct,
                (MapBinding<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET>)BindingStructures.CreateBinding);
        }
        
        private static List<CertificateBinding> QueryManyIpEndpoints()
        {
            var result = new List<CertificateBinding>();

            HttpApi.CallHttpApi(
                delegate
                {
                    uint token = 0;
                    uint retVal;
                    do
                    {
                        var queryStruct = new HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY
                        {
                            QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
                            dwToken = token,
                        };
                        IntPtr queryStructPtr = StructureToPtr(queryStruct);

                        IntPtr bindingStructPtr = IntPtr.Zero;
                        int returnLength = 0;

                        try
                        {
                            int queryStructSize = Marshal.SizeOf(queryStruct);
                            retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
                                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                                queryStructPtr,
                                queryStructSize,
                                bindingStructPtr,
                                returnLength,
                                out returnLength,
                                IntPtr.Zero);
                            if (HttpApi.ERROR_NO_MORE_ITEMS == retVal)
                                break;
                            if (HttpApi.ERROR_INSUFFICIENT_BUFFER == retVal)
                            {
                                bindingStructPtr = Marshal.AllocCoTaskMem(returnLength);

                                try
                                {
                                    retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
                                        HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                                        queryStructPtr,
                                        queryStructSize,
                                        bindingStructPtr,
                                        returnLength,
                                        out returnLength,
                                        IntPtr.Zero);
                                    HttpApi.ThrowWin32ExceptionIfError(retVal);

                                    var bindingStruct = (HttpApi.HTTP_SERVICE_CONFIG_SSL_SET)Marshal.PtrToStructure(
                                        bindingStructPtr, typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET));
                                    CertificateBinding resultItem = BindingStructures.CreateBinding(bindingStruct);
                                    result.Add(resultItem);
                                    token++;
                                }
                                finally
                                {
                                    Marshal.FreeCoTaskMem(bindingStructPtr);
                                }
                            }
                            else
                            {
                                HttpApi.ThrowWin32ExceptionIfError(retVal);
                            }
                        }
                        finally
                        {
                            Marshal.FreeCoTaskMem(queryStructPtr);
                        }

                    } while (HttpApi.NOERROR == retVal);
                });

            return result;
        }

        private static List<CertificateBinding> QueryManyDnsEndpoints()
        {
            var result = new List<CertificateBinding>();

            HttpApi.CallHttpApi(
                delegate
                {
                    uint token = 0;
                    uint retVal;
                    do
                    {
                        var queryStruct = new HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY
                        {
                            QueryDesc = HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE.HttpServiceConfigQueryNext,
                            dwToken = token,
                        };
                        IntPtr queryStructPtr = StructureToPtr(queryStruct);

                        IntPtr bindingStructPtr = IntPtr.Zero;
                        int returnLength = 0;

                        try
                        {
                            int queryStructSize = Marshal.SizeOf(queryStruct);
                            retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
                                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo,
                                queryStructPtr,
                                queryStructSize,
                                bindingStructPtr,
                                returnLength,
                                out returnLength,
                                IntPtr.Zero);
                            if (HttpApi.ERROR_NO_MORE_ITEMS == retVal)
                                break;
                            if (HttpApi.ERROR_INSUFFICIENT_BUFFER == retVal)
                            {
                                bindingStructPtr = Marshal.AllocCoTaskMem(returnLength);

                                try
                                {
                                    retVal = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
                                        HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo,
                                        queryStructPtr,
                                        queryStructSize,
                                        bindingStructPtr,
                                        returnLength,
                                        out returnLength,
                                        IntPtr.Zero);
                                    HttpApi.ThrowWin32ExceptionIfError(retVal);

                                    var bindingStruct = (HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET)Marshal.PtrToStructure(
                                        bindingStructPtr, typeof(HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET));
                                    CertificateBinding resultItem = BindingStructures.CreateBinding(bindingStruct);
                                    result.Add(resultItem);
                                    token++;
                                }
                                finally
                                {
                                    Marshal.FreeCoTaskMem(bindingStructPtr);
                                }
                            }
                            else
                            {
                                HttpApi.ThrowWin32ExceptionIfError(retVal);
                            }
                        }
                        finally
                        {
                            Marshal.FreeCoTaskMem(queryStructPtr);
                        }

                    } while (HttpApi.NOERROR == retVal);
                });

            return result;
        }

        private static IntPtr StructureToPtr<TStruct>(TStruct structObj) where TStruct : struct
        {
            IntPtr structPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(structObj.GetType()));
            Marshal.StructureToPtr(structObj, structPtr, false);
            return structPtr;
        }
    }
}
