using System;
using System.Net;

namespace SslCertBinding.Net
{
    public static class BindingEndPointExtentions
    {
        public static BindingEndPoint ToBindingEndPoint(this IPEndPoint ipEndPoint) => new BindingEndPoint(ipEndPoint);
        public static BindingEndPoint ToBindingEndPoint(this DnsEndPoint dnsEndPoint) => dnsEndPoint as BindingEndPoint ?? new BindingEndPoint(dnsEndPoint);
        public static DnsEndPoint ToDnsEndPoint(this IPEndPoint ipEndPoint) => ipEndPoint.ThrowIfNull(nameof(ipEndPoint)).ToBindingEndPoint();
        public static IPEndPoint ToIPEndPoint(this DnsEndPoint dnsEndPoint) => dnsEndPoint.ThrowIfNull(nameof(dnsEndPoint)).ToBindingEndPoint().ToIPEndPoint();
    }
}
