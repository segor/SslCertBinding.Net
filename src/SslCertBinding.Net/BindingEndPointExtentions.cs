using System;
using System.Net;

namespace SslCertBinding.Net
{
    public static class BindingEndPointExtentions
    {       
        public static BindingEndPoint ToBindingEndPoint(this DnsEndPoint dnsEndPoint) => new BindingEndPoint(dnsEndPoint);

        public static BindingEndPoint ToBindingEndPoint(this IPEndPoint ipEndPoint) => new BindingEndPoint(ipEndPoint);

        public static IPEndPoint ToIPEndPoint(this DnsEndPoint dnsEndPoint) => dnsEndPoint.ToBindingEndPoint().ToIPEndPoint();
    }
}
