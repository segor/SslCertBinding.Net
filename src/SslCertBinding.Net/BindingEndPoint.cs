using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SslCertBinding.Net
{
    /// <summary>
    ///  Represents a network endpoint as a host name or a string representation of an IP address and a port number.
    /// </summary>
    public class BindingEndPoint : EndPoint, IEquatable<BindingEndPoint>, IEquatable<IPEndPoint>, IEquatable<DnsEndPoint>
    {
        private readonly DnsEndPoint _dnsEndpoint;
        private readonly IPEndPoint _ipEndPoint;

        /// <summary>
        /// Gets the host name or text representation of the IP address of the endpoint.
        /// </summary>
        public string Host => _dnsEndpoint.Host;

        /// <summary>
        /// Gets the port number of the endpoint.
        /// </summary>
        public int Port => _dnsEndpoint.Port;

        /// <summary>
        /// Gets the address family of the endpoint.
        /// </summary>
        public override AddressFamily AddressFamily => _ipEndPoint?.AddressFamily ?? _dnsEndpoint.AddressFamily;

        /// <summary>
        /// Gets a value indicating whether this endpoint is based on IP address.
        /// </summary>
        public bool IsIpEndpoint => _ipEndPoint != null;

        /// <summary>
        /// Initializes a new instance of the <see cref="BindingEndPoint"/> class with the specified host and port.
        /// </summary>
        /// <param name="hostOrIp">Host or IP address</param>
        /// <param name="port"></param>
        public BindingEndPoint(string hostOrIp, int port) : this(
                hostOrIp.ThrowIfNull(nameof(hostOrIp)),
                port,
                TryParseIPEndpoint(hostOrIp, port))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BindingEndPoint"/> class with the specified IP address and port.
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="port"></param>
        public BindingEndPoint(IPAddress ipAddress, int port)
            : this(new IPEndPoint(ipAddress.ThrowIfNull(nameof(ipAddress)), port))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BindingEndPoint"/> class with the specified IP endpoint.
        /// </summary>
        /// <param name="ipEndPoint"><see cref="IPEndPoint"/></param>
        public BindingEndPoint(IPEndPoint ipEndPoint) : this(
            ipEndPoint.ThrowIfNull(nameof(ipEndPoint)).Address.ToString(),
            ipEndPoint.Port,
            ipEndPoint)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BindingEndPoint"/> class with the specified DNS endpoint.
        /// </summary>
        /// <param name="dnsEndPoint">A network endpoint as a host name or a string representation of an IP address and a port number</param>
        public BindingEndPoint(DnsEndPoint dnsEndPoint)
        {
            _dnsEndpoint = dnsEndPoint.ThrowIfNull(nameof(dnsEndPoint));
            _ipEndPoint = TryParseIPEndpoint(dnsEndPoint.Host, dnsEndPoint.Port);
        }

        private BindingEndPoint(string host, int port, IPEndPoint ipEndPoint)
        {
            _dnsEndpoint = new DnsEndPoint(
                ipEndPoint == null ? host : ipEndPoint.Address.ToString(),
                port,
                ipEndPoint?.AddressFamily ?? AddressFamily.Unspecified);
            _ipEndPoint = ipEndPoint;
        }

        /// <summary>
        /// Implicitly converts an <see cref="IPEndPoint"/> to a <see cref="BindingEndPoint"/>.
        /// </summary>
        /// <param name="ipEndPoint"></param>
        public static implicit operator BindingEndPoint(IPEndPoint ipEndPoint) => ipEndPoint == null ? null : new BindingEndPoint(ipEndPoint);

        /// <summary>
        /// Implicitly converts an <see cref="DnsEndPoint"/> to a <see cref="BindingEndPoint"/>.
        /// </summary>
        /// <param name="dnsEndPoint">A network endpoint as a host name or a string representation of an IP address and a port number</param>
        public static implicit operator BindingEndPoint(DnsEndPoint dnsEndPoint) => dnsEndPoint == null ? null : new BindingEndPoint(dnsEndPoint);


        /// <summary>
        /// Converts this <see cref="BindingEndPoint"/> to an <see cref="IPEndPoint"/> if it is an IP endpoint.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException">if the endpoint is not IP address</exception>
        public IPEndPoint ToIPEndPoint()
        {
            if (!IsIpEndpoint)
                throw new InvalidOperationException("Endpoint is not IP address");
            return _ipEndPoint;
        }


        /// <summary>
        /// Converts this <see cref="BindingEndPoint"/> to a <see cref="DnsEndPoint"/> if it is a DNS endpoint.
        /// </summary>
        /// <returns>A network endpoint as a host name or a string representation of an IP address and a port number</returns>
        public DnsEndPoint ToDnsEndPoint() => _dnsEndpoint;

        /// <summary>
        /// Returns a string representation of the endpoint.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            if (IsIpEndpoint)
            {
                return _ipEndPoint.ToString();
            }
            return $"{_dnsEndpoint.Host}:{Port.ToString(CultureInfo.InvariantCulture)}";
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current <see cref="BindingEndPoint"/>.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            switch (obj)
            {
                case BindingEndPoint bindingEndPoint:
                    return Equals(bindingEndPoint);
                case IPEndPoint ipEndPoint:
                    return Equals(ipEndPoint);
                case DnsEndPoint dnsEndPoint:
                    return Equals(dnsEndPoint);
            }

            return false;
        }

        /// <summary>
        /// Determines whether the specified <see cref="BindingEndPoint"/> is equal to the current <see cref="BindingEndPoint"/>.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        bool IEquatable<BindingEndPoint>.Equals(BindingEndPoint other)
        {
            if (other == null)
                return false;
            return _dnsEndpoint.Equals(other._dnsEndpoint);
        }

        /// <summary>
        /// Determines whether the specified <see cref="DnsEndPoint"/> is equal to the current <see cref="BindingEndPoint"/>.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        bool IEquatable<DnsEndPoint>.Equals(DnsEndPoint other)
        {
            if (other == null)
                return false;
            return _dnsEndpoint.Equals(other);
        }

        /// <summary>
        /// Determines whether the specified <see cref="IPEndPoint"/> is equal to the current <see cref="BindingEndPoint"/>.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        bool IEquatable<IPEndPoint>.Equals(IPEndPoint other)
        {
            if (other == null || _ipEndPoint == null)
                return false;
            return _ipEndPoint.Equals(other);
        }


        /// <summary>
        /// Returns a hash code for the current <see cref="BindingEndPoint"/>.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode() => _dnsEndpoint.GetHashCode();

        /// <summary>
        /// Tries to parse a string representation of an endpoint into a <see cref="BindingEndPoint"/> instance.
        /// </summary>
        /// <param name="endpointStr"></param>
        /// <param name="endPoint"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">if endpointStr is null</exception>
        public static bool TryParse(string endpointStr, out BindingEndPoint endPoint)
        {
            endPoint = null;
            endpointStr = endpointStr.ThrowIfNull(nameof(endpointStr)).Trim();
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

        /// <summary>
        /// Parses a string representation of an endpoint into a <see cref="BindingEndPoint"/> instance.
        /// </summary>
        /// <param name="endpointStr"></param>
        /// <returns></returns>
        /// <exception cref="FormatException">Invalid endpoint format</exception>
        public static BindingEndPoint Parse (string endpointStr)
        {
            if (!TryParse(endpointStr, out BindingEndPoint endPoint))
            {
                throw new FormatException($"Invalid endpoint format: {endpointStr}");
            }
            return endPoint;
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
