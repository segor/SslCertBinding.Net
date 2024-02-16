using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SslCertBinding.Net
{
    public class BindingEndPoint : DnsEndPoint
    {
        private IPEndPoint _ipEndPoint { get; }

        public bool IsIpEndpoint => _ipEndPoint != null;
        public IPAddress IPAddress => _ipEndPoint?.Address;

        public BindingEndPoint(string host, int port)
            : this(host, port, TryGetIPAddressFromHostArgument(host))
        {
        }

        public BindingEndPoint(IPAddress ipAddress, int port)
            : this(ipAddress.ToString(), port, ipAddress)
        {
            if (ipAddress is null)
            {
                throw new ArgumentNullException(nameof(ipAddress));
            }
        }

        public BindingEndPoint(IPEndPoint ipEndPoint)
            : this(ipEndPoint.Address, ipEndPoint.Port)
        {
            if (ipEndPoint is null)
            {
                throw new ArgumentNullException(nameof(ipEndPoint));
            }
        }

        public BindingEndPoint(DnsEndPoint dnsEndPoint)
            : this(dnsEndPoint.Host, dnsEndPoint.Port)
        {
            if (dnsEndPoint is null)
            {
                throw new ArgumentNullException(nameof(dnsEndPoint));
            }
        }

        private BindingEndPoint(string host, int port, IPAddress ipAddress)
            : base(host, port, ipAddress?.AddressFamily ?? AddressFamily.Unspecified)
        {            
            _ipEndPoint = ipAddress == null
                ? null
                : new IPEndPoint(ipAddress, port);
        }

        //public static implicit operator BindingEndPoint(IPEndPoint ipEndPoint) => ipEndPoint == null ? null : new BindingEndPoint(ipEndPoint);

        public IPEndPoint ToIPEndPoint()
        {
            if (!IsIpEndpoint)
                throw new InvalidOperationException("Endpoint is not IP address.");
            return _ipEndPoint;
        }

        public override string ToString()
        {
            if (IsIpEndpoint)
                return ToIPEndPoint().ToString();
            return $"{Host}:{Port.ToString(CultureInfo.InvariantCulture)}";
        }

        public static bool TryParse(string endpointStr, out BindingEndPoint endPoint)
        {
            endPoint = null;
            endpointStr = endpointStr ?? throw new ArgumentNullException(nameof(endpointStr));
            endpointStr = endpointStr.Trim();
            int portSeparatorIndex = endpointStr.LastIndexOf(':');
            if (portSeparatorIndex == -1)
                return false;

            string host = endpointStr.Substring(0, portSeparatorIndex).Trim();
            string portStr = endpointStr.Substring(portSeparatorIndex + 1).Trim();

            if (string.IsNullOrEmpty(host))
                return false;

            if (!int.TryParse(portStr, out int port) || port < 0 || port > 65535)
                return false;

            endPoint = IPAddress.TryParse(host, out IPAddress ip)
                ? new BindingEndPoint(ip, port)
                : new BindingEndPoint(host, port);
            return true;
        }

        private static IPAddress TryGetIPAddressFromHostArgument(string host)
        {
            if (host is null)
            {
                throw new ArgumentNullException(nameof(host));
            }

            return IPAddress.TryParse(host, out IPAddress ip)
                ? ip
                : null;
        }
    }
}
