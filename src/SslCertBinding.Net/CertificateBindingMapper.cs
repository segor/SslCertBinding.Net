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
            var options = CreateBindingOptions(bindingStruct.ParamDesc);
            var result = new CertificateBinding(GetThumbrint(hash), storeName, endPoint, appId, options);
            return result;
        }

        private static BindingOptions CreateBindingOptions(HttpApi.HTTP_SERVICE_CONFIG_SSL_PARAM paramDesc)
        {
            HttpApi.CertCheckModes checkModes = paramDesc.DefaultCertCheckMode;
            return new BindingOptions
            {
                DoNotVerifyCertificateRevocation = HasFlag(checkModes, HttpApi.CertCheckModes.DoNotVerifyCertificateRevocation),
                VerifyRevocationWithCachedCertificateOnly = HasFlag(checkModes, HttpApi.CertCheckModes.VerifyRevocationWithCachedCertificateOnly),
                EnableRevocationFreshnessTime = HasFlag(checkModes, HttpApi.CertCheckModes.EnableRevocationFreshnessTime),
                NoUsageCheck = HasFlag(checkModes, HttpApi.CertCheckModes.NoUsageCheck),
                RevocationFreshnessTime = TimeSpan.FromSeconds(paramDesc.DefaultRevocationFreshnessTime),
                RevocationUrlRetrievalTimeout = TimeSpan.FromMilliseconds(paramDesc.DefaultRevocationUrlRetrievalTimeout),
                SslCtlIdentifier = paramDesc.pDefaultSslCtlIdentifier,
                SslCtlStoreName = paramDesc.pDefaultSslCtlStoreName,
                NegotiateCertificate = HasFlag(paramDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NEGOTIATE_CLIENT_CERT),
                UseDsMappers = HasFlag(paramDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.USE_DS_MAPPER),
                DoNotPassRequestsToRawFilters = HasFlag(paramDesc.DefaultFlags, HttpApi.HTTP_SERVICE_CONFIG_SSL_FLAG.NO_RAW_FILTER),
            };
        }

        private static string GetThumbrint(byte[] hash)
        {
            string thumbrint = BitConverter.ToString(hash).Replace("-", "");
            return thumbrint;
        }

        private static bool HasFlag(uint value, uint flag)
        {
            return (value & flag) == flag;
        }

        private static bool HasFlag<T>(T value, T flag) where T : IConvertible
        {
            uint uintValue = Convert.ToUInt32(value, CultureInfo.InvariantCulture);
            uint uintFlag = Convert.ToUInt32(flag, CultureInfo.InvariantCulture);
            return HasFlag(uintValue, uintFlag);
        }
    }
}
