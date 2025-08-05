using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SslCertBinding.Net
{

    public class BindingEndPoint : DnsEndPoint
    {
        private IPEndPoint _ipEndPoint;

        public bool IsIpEndpoint => _ipEndPoint != null;

        public BindingEndPoint(string host, int port) : this(
                host.ThrowIfNull(nameof(host)),
                port,
                TryParseIPEndpoint(host, port))
        {
        }

        public BindingEndPoint(IPAddress ipAddress, int port)
            : this(new IPEndPoint(ipAddress.ThrowIfNull(nameof(ipAddress)), port))
        {
        }

        public BindingEndPoint(IPEndPoint ipEndPoint) : this(
            ipEndPoint.ThrowIfNull(nameof(ipEndPoint)).Address.ToString(),
            ipEndPoint.Port,
            ipEndPoint)
        {
            if (ipEndPoint is null)
            {
                throw new ArgumentNullException(nameof(ipEndPoint));
            }
        }

        internal protected BindingEndPoint(DnsEndPoint dnsEndPoint) : this(
            dnsEndPoint.ThrowIfNull(nameof(dnsEndPoint)).Host,
            dnsEndPoint.Port)
        {
        }

        private BindingEndPoint(string host, int port, IPEndPoint ipEndPoint)
            : base(host, port, ipEndPoint?.AddressFamily ?? AddressFamily.Unspecified)
        {
            _ipEndPoint = ipEndPoint;
        }

        public static implicit operator BindingEndPoint(IPEndPoint ipEndPoint) => ipEndPoint == null ? null : new BindingEndPoint(ipEndPoint);

        public IPEndPoint ToIPEndPoint()
        {
            if (!IsIpEndpoint)
                throw new InvalidOperationException("Endpoint is not IP address");
            return _ipEndPoint;
        }

        public override string ToString()
        {
            if (IsIpEndpoint)
                return _ipEndPoint.ToString();
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

        private static IPEndPoint TryParseIPEndpoint(string host, int port)
        {
            if (!IPAddress.TryParse(host, out IPAddress ipAddress))
            {
                return null;
            }
            return new IPEndPoint(ipAddress, port);
        }
    }
}
