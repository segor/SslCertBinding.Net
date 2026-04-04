using System;
using System.Net;

namespace SslCertBinding.Net
{
    public static class BindingEndPointExtentions
    {       
        public static BindingEndPoint ToBindingEndPoint(this DnsEndPoint dnsEndPoint)
        {
            if (dnsEndPoint == null)
            {
                throw new ArgumentNullException(nameof(dnsEndPoint));
            }

            return BindingEndPoint.Create(dnsEndPoint.Host, dnsEndPoint.Port);
        }

        public static IpPort ToBindingEndPoint(this IPEndPoint ipEndPoint) => new IpPort(ipEndPoint);
    }
}
