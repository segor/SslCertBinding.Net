using System;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;

namespace SslCertBinding.Net
{
    internal static class CertificateBindingMapper
    {
        public static CertificateBinding CreateCertificateBindingInfo(HttpApi.HTTP_SERVICE_CONFIG_SSL_SET bindingStruct)
        {
            byte[] hash = new byte[bindingStruct.ParamDesc.SslHashLength];
            Marshal.Copy(bindingStruct.ParamDesc.pSslHash, hash, 0, hash.Length);
            Guid appId = bindingStruct.ParamDesc.AppId;
            string storeName = bindingStruct.ParamDesc.pSslCertStoreName;
            IPEndPoint ipPort = SockaddrInterop.ReadSockaddrStructure(bindingStruct.KeyDesc.pIpPort);
            BindingOptions options = CreateBindingOptions(bindingStruct.ParamDesc);
            var result = new CertificateBinding(GetThumbrint(hash), storeName, ipPort, appId, options);
            return result;
        }

        public static CertificateBinding CreateCertificateBindingInfo(HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET bindingStruct)
        {
            byte[] hash = new byte[bindingStruct.ParamDesc.SslHashLength];
            Marshal.Copy(bindingStruct.ParamDesc.pSslHash, hash, 0, hash.Length);
            Guid appId = bindingStruct.ParamDesc.AppId;
            string storeName = bindingStruct.ParamDesc.pSslCertStoreName;
            IPEndPoint ipPort = SockaddrInterop.CreateIPEndPoint(bindingStruct.KeyDesc.IpPort);
            var endPoint = new BindingEndPoint(bindingStruct.KeyDesc.Host, ipPort.Port);
            BindingOptions options = CreateBindingOptions(bindingStruct.ParamDesc);
            var result = new CertificateBinding(GetThumbrint(hash), storeName, endPoint, appId, options);
            return result;
        }

        public static HttpApi.HTTP_SERVICE_CONFIG_SSL_SET CreateBindingStruct(CertificateBinding binding, out Action freeResourcesFunc)
        {
            IntPtr ipPortPtr = SockaddrInterop.CreateSockaddrStructure(binding.EndPoint.ToIPEndPoint(), out Action freeSockAddress);
            byte[] hashBytes = GetHashBytes(binding.Thumbprint);
            GCHandle hashBytesHandle = GCHandle.Alloc(hashBytes, GCHandleType.Pinned);
            IntPtr hashBytesPtr = hashBytesHandle.AddrOfPinnedObject();

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
                pSslHash = hashBytesPtr,
                SslHashLength = hashBytes.Length,
                pDefaultSslCtlIdentifier = options.SslCtlIdentifier,
                pDefaultSslCtlStoreName = options.SslCtlStoreName
            };

            freeResourcesFunc = () =>
            {
                if (hashBytesHandle.IsAllocated)
                    hashBytesHandle.Free();
                freeSockAddress();
            };

            return new HttpApi.HTTP_SERVICE_CONFIG_SSL_SET
            {
                ParamDesc = configSslParam,
                KeyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(ipPortPtr)
            };
        }

        public static HttpApi.HTTP_SERVICE_CONFIG_SSL_SET CreateBindingStructForDeletion(BindingEndPoint endPoint, out Action freeResourcesFunc)
        {
            IPEndPoint ipPort = endPoint.ToIPEndPoint();
            IntPtr ipPortPtr = SockaddrInterop.CreateSockaddrStructure(ipPort, out Action freeSockaddr);
            freeResourcesFunc = () => freeSockaddr();

            return new HttpApi.HTTP_SERVICE_CONFIG_SSL_SET
            {
                KeyDesc = new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(ipPortPtr)
            };
        }

        private static byte[] GetHashBytes(string thumbprint)
        {
            int length = thumbprint.Length;
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
                bytes[i / 2] = Convert.ToByte(thumbprint.Substring(i, 2), 16);
            return bytes;
        }

        private static string GetThumbrint(byte[] hash) => BitConverter.ToString(hash).Replace("-", "");

        private static BindingOptions CreateBindingOptions(HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM paramDesc) => new BindingOptions
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
        };

        private static bool HasFlag<T>(T value, T flag) where T : Enum
        {
            uint uintValue = Convert.ToUInt32(value, CultureInfo.InvariantCulture);
            uint uintFlag = Convert.ToUInt32(flag, CultureInfo.InvariantCulture);
            return (uintValue & uintFlag) == uintFlag;
        }
    }
}
