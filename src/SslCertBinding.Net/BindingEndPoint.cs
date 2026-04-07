using System;
using System.Globalization;
using System.Net;

namespace SslCertBinding.Net
{

    public enum BindingHostType
    {
        IpAddress,
        Hostname,
        AnyHost
    }


    public interface IBindingEndPoint
    {

        string Host { get; }
        int Port { get; }


        EndPoint ToEndPoint();

    }

    public abstract class BindingEndPoint : IBindingEndPoint
    {
        public BindingEndPoint(string host, int port)
        {
            Host = host;
            Port = port;
        }

        public string Host { get; }
        public int Port { get; }

        public bool IsIpEndpoint => this is IpPort;

        public abstract EndPoint ToEndPoint();
        public abstract IPEndPoint ToIPEndPoint();
        public abstract DnsEndPoint ToDnsEndPoint();

        /// <summary>
        /// Tries to parse a string representation of an endpoint into a <see cref="BindingEndPoint"/> instance.
        /// </summary>
        /// <param name="endpointStr"></param>
        /// <param name="endPoint"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">if endpointStr is null</exception>
        public static bool TryParse(string endpointStr, out BindingEndPoint endPoint)
        {
            if (AnyHostPort.TryParse(endpointStr, out AnyHostPort anyHostPort))
            {
                endPoint = anyHostPort;
                return true;
            }
            
            if (IpPort.TryParse(endpointStr, out IpPort ipPort))
            {
                endPoint = ipPort;
                return true;
            }

            if (HostnamePort.TryParse(endpointStr, out HostnamePort hostnamePort))
            {
                endPoint = hostnamePort;
                return true;
            }

            endPoint = null;
            return false;
        }

        public static BindingEndPoint Parse(string endpointStr)
        {
            if (!TryParse(endpointStr.ThrowIfNull(nameof(endpointStr)), out BindingEndPoint endPoint))
            {
                throw new FormatException("Invalid endpoint format.");
            }
            return endPoint;
        }

        public static BindingEndPoint Create(string host, int port)
        {
            if (AnyHostPort.TryParse(host, port, out AnyHostPort anyHostPort))
            {
                return anyHostPort;
            }
            else if (IpPort.TryParse(host, port, out IpPort ipPort))
            {
                return ipPort;
            }
             
            return new HostnamePort(host, port);
        }     
    }

    internal static class BindingEndPointParser
    {

        public static bool TryParse(string endpointStr, out BindingEndPoint endPoint)
        {
            if (AnyHostPort.TryParse(endpointStr, out AnyHostPort anyHostPort))
            {
                endPoint = anyHostPort;
                return true;
            }
            
            if (IpPort.TryParse(endpointStr, out IpPort ipPort))
            {
                endPoint = ipPort;
                return true;
            }

            if (HostnamePort.TryParse(endpointStr, out HostnamePort hostnamePort))
            {
                endPoint = hostnamePort;
                return true;
            }

            endPoint = null;
            return false;
        } 

        internal static bool TryParseHostPort(string endpointStr, out string host, out int port)
        {

            host = null;
            port = 0;

            if (string.IsNullOrEmpty(endpointStr))
                return false;

            endpointStr = endpointStr.Trim();
            int portSeparatorIndex = endpointStr.LastIndexOf(':');
            if (portSeparatorIndex == -1)
                return false;

            string hostParsed = endpointStr.Substring(0, portSeparatorIndex).Trim();
            string portStr = endpointStr.Substring(portSeparatorIndex + 1).Trim();

            if (string.IsNullOrEmpty(hostParsed))
                return false;
            
            if (!TryParsePort(portStr, out int portParsed))
                return false;

            host = hostParsed;
            port = portParsed;
            return true;
        }

        internal static bool TryParsePort(string portStr, out int port)
        {
            return int.TryParse(portStr, out port) 
                && IsValidPort(port);
        }

        internal static bool IsValidPort(int port)
        {
            return port >= IPEndPoint.MinPort && port <= IPEndPoint.MaxPort;
        }

    }

    public class IpPort : BindingEndPoint, IEquatable<IpPort>, IEquatable<IPEndPoint>
    {
        private const string FormatErrorMessage = "Invalid IP endpoint format.";

        private readonly IPEndPoint _endPoint;

        /// <summary>
        /// Initializes a new instance of the <see cref="BindingEndPoint"/> class with the specified IP address and port.
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="port">Port number. Must be between <see cref="System.Net.IPEndPoint.MinPort"/> and <see cref="System.Net.IPEndPoint.MaxPort"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipAddress"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="port"/> is outside the range <see cref="System.Net.IPEndPoint.MinPort"/> to <see cref="System.Net.IPEndPoint.MaxPort"/>.</exception>
        public IpPort(IPAddress ipAddress, int port)
            : this(new IPEndPoint(ipAddress.ThrowIfNull(nameof(ipAddress)), port))
        {
        }

        public IpPort(IPEndPoint ipEndPoint) : base(ipEndPoint.ThrowIfNull(nameof(ipEndPoint)).Address.ToString(), ipEndPoint.Port)
        {
            _endPoint = ipEndPoint.ThrowIfNull(nameof(ipEndPoint));
        }

        public IPAddress Address => _endPoint.Address;

        public override EndPoint ToEndPoint() => ToIPEndPoint();

        public override IPEndPoint ToIPEndPoint() => _endPoint;
        public override DnsEndPoint ToDnsEndPoint() => new DnsEndPoint(Host, Port);
        
        /// <summary>
        /// Returns a string representation of the endpoint.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
           return _endPoint.ToString();
        }

        public bool Equals(IpPort other)
        {
            if (other == null)
                return false;

            return _endPoint.Equals(other._endPoint);
        }

        public bool Equals(IPEndPoint other) => _endPoint.Equals(other);

        public override bool Equals(object obj)
        {
            switch (obj)
            {
                case IPEndPoint ipEndPoint:
                    return Equals(ipEndPoint);
                case IpPort ipPort:
                    return Equals(ipPort);
                default:
                    return false;
            }
        }


        public override int GetHashCode()
            => _endPoint.GetHashCode();

        /// <summary>
        /// Tries to parse a string representation of an endpoint into a <see cref="BindingEndPoint"/> instance.
        /// </summary>
        /// <param name="ipPortStr"></param>
        /// <param name="endPoint"></param>
        /// <returns></returns>
        public static bool TryParse(string ipPortStr, out IpPort endPoint)
        {
            endPoint = null;

            if (!BindingEndPointParser.TryParseHostPort(ipPortStr, out string host, out int port))
                return false;

            return TryParse(host, port, out endPoint);
        }

        public static bool TryParse(string host, int port, out IpPort endPoint)
        {
            endPoint = null;

            if (!BindingEndPointParser.IsValidPort(port))
                return false;

            if (!IPAddress.TryParse(host, out IPAddress ip))
                return false;
            var ipEndPoint = new IPEndPoint(ip, port);

            endPoint = new IpPort(ipEndPoint);
            return true;
        }


        /// <summary>
        /// Parses a string representation of an endpoint into a <see cref="BindingEndPoint"/> instance.
        /// </summary>
        /// <param name="ipPortStr"></param>
        /// <returns></returns>
        /// <exception cref="FormatException">Invalid endpoint format</exception>
        /// <exception cref="ArgumentNullException">endpointStr is null</exception>
        public static new IpPort Parse(string ipPortStr)
        {
            if (!TryParse(ipPortStr.ThrowIfNull(nameof(ipPortStr)), out IpPort endPoint))
            {
                throw new FormatException(FormatErrorMessage);
            }
            return endPoint;
        }
    }

     public class HostnamePort : BindingEndPoint, IEquatable<HostnamePort>, IEquatable<DnsEndPoint>
    {
        private const string FormatErrorMessage = "Invalid DNS endpoint format.";

        private readonly DnsEndPoint _endPoint;
        
        public HostnamePort(string hostname, int port)
            : this(new DnsEndPoint(hostname.ThrowIfNullOrEmpty(nameof(hostname)), port))
        {            
        }

        public HostnamePort(DnsEndPoint dnsEndPoint) : base(dnsEndPoint.ThrowIfNull(nameof(dnsEndPoint)).Host, dnsEndPoint.Port)
        {
            if (IPAddress.TryParse(dnsEndPoint.Host, out _))
            {
                throw new ArgumentException("Host cannot be an IP address.", nameof(dnsEndPoint));
            }
            _endPoint = dnsEndPoint.ThrowIfNull(nameof(dnsEndPoint));
        }


        public override DnsEndPoint ToDnsEndPoint() => _endPoint;

        public override EndPoint ToEndPoint() =>  ToDnsEndPoint();

        public override IPEndPoint ToIPEndPoint()
        {
            throw new InvalidCastException("Cannot convert a hostname endpoint to an IPEndPoint.");
        }

        /// <summary>
        /// Returns a string representation of the endpoint.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {            
            return $"{Host}:{Port.ToString(CultureInfo.InvariantCulture)}";
        }

         public bool Equals(HostnamePort other)
        {
            if (other == null)
                return false;

            return _endPoint.Equals(other._endPoint);
        }

        public bool Equals(DnsEndPoint other) => _endPoint.Equals(other);

        public override bool Equals(object obj)
        {
            switch (obj)
            {
                case DnsEndPoint dnsEndPoint:
                    return Equals(dnsEndPoint);
                case HostnamePort hostnamePort:
                    return Equals(hostnamePort);
                default:
                    return false;
            }
            
        }


        public override int GetHashCode()
            => _endPoint.GetHashCode();



        /// <summary>
        /// Tries to parse a string representation of an endpoint into a <see cref="BindingEndPoint"/> instance.
        /// </summary>
        /// <param name="hostnamePortStr"></param>
        /// <param name="endPoint"></param>
        /// <returns></returns>
        public static bool TryParse(string hostnamePortStr, out HostnamePort endPoint)
        {         
            endPoint = null;

            if(!BindingEndPointParser.TryParseHostPort(hostnamePortStr, out string host, out int port))
                return false;

            return TryParse(host, port, out endPoint);
        }

        public static bool TryParse(string host, int port, out HostnamePort endPoint)
        {
            endPoint = null;

            if (!BindingEndPointParser.IsValidPort(port))
                return false;

            if (IPAddress.TryParse(host, out _))
                return false;

            var dnsEndPoint = new DnsEndPoint(host, port);

            endPoint = new HostnamePort(dnsEndPoint);
            return true;
        }


        /// <summary>
        /// Parses a string representation of an endpoint into a <see cref="BindingEndPoint"/> instance.
        /// </summary>
        /// <param name="hostnamePortStr"></param>
        /// <returns></returns>
        /// <exception cref="FormatException">Invalid endpoint format</exception>
        /// <exception cref="ArgumentNullException">endpointStr is null</exception>
        public static new HostnamePort Parse(string hostnamePortStr)
        {
            if (!TryParse(hostnamePortStr.ThrowIfNull(nameof(hostnamePortStr)), out HostnamePort endPoint))
            {
                throw new FormatException(FormatErrorMessage);
            }
            return endPoint;
        }

        

    }


     public class AnyHostPort : BindingEndPoint, IEquatable<AnyHostPort>, IEquatable<int>
    {
        private const string FormatErrorMessage = "Invalid port format.";
        private const string AnyHostname = "*";
        private readonly IPEndPoint _endPoint;

        /// <summary>
        /// Initializes a new instance of the <see cref="BindingEndPoint"/> class with the specified IP address and port.
        /// </summary>
        /// <param name="port">Port number. Must be between <see cref="System.Net.IPEndPoint.MinPort"/> and <see cref="System.Net.IPEndPoint.MaxPort"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipAddress"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="port"/> is outside the range <see cref="System.Net.IPEndPoint.MinPort"/> to <see cref="System.Net.IPEndPoint.MaxPort"/>.</exception>
        public AnyHostPort(int port) : base(string.Empty, port)
        {
            _endPoint = new IPEndPoint(IPAddress.Any, port);
        }
        public override EndPoint ToEndPoint() => ToIPEndPoint();

        public override IPEndPoint ToIPEndPoint() => _endPoint;
        public override DnsEndPoint ToDnsEndPoint() => new DnsEndPoint(Host, Port);
        /// <summary>
        /// Returns a string representation of the endpoint.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
           return _endPoint.Port.ToString(CultureInfo.InvariantCulture);
        }

        public bool Equals(AnyHostPort other)
        {
            if (other == null)
                return false;

            return Port.Equals(other.Port);
        }

        public bool Equals(int other) => Port == other;

        public override bool Equals(object obj)
        { 
            switch(obj)
            {
                case int port:
                    return Equals(port);
                case AnyHostPort anyHostPort:
                    return Equals(anyHostPort);
                default:
                    return false;
            }
        }

        public override int GetHashCode()
            => Port.GetHashCode();

        /// <summary>
        /// Tries to parse a string representation of an endpoint into a <see cref="BindingEndPoint"/> instance.
        /// </summary>
        /// <param name="portStr"></param>
        /// <param name="endPoint"></param>
        /// <returns></returns>
        public static bool TryParse(string portStr, out AnyHostPort endPoint)
        {         
            endPoint = null;

            if (int.TryParse(portStr, out int port) && port >= 0 && port <= 65535)
            {
                endPoint = new AnyHostPort(port);
                return true;
            }

            return false;
        }

        internal static bool TryParse(string host, int port, out AnyHostPort endPoint)
        {
            endPoint = null;

            if (!BindingEndPointParser.IsValidPort(port))
                return false;

            if (string.IsNullOrEmpty(host) || host == AnyHostname)
            {
                endPoint = new AnyHostPort(port);
                return true;
            }

            return false;
        }


        /// <summary>
        /// Parses a string representation of an endpoint into a <see cref="BindingEndPoint"/> instance.
        /// </summary>
        /// <param name="portStr"></param>
        /// <returns></returns>
        /// <exception cref="FormatException">Invalid endpoint format</exception>
        /// <exception cref="ArgumentNullException">endpointStr is null</exception>
        public static new AnyHostPort Parse(string portStr)
        {
            if (!TryParse(portStr.ThrowIfNull(nameof(portStr)), out AnyHostPort endPoint))
            {
                throw new FormatException(FormatErrorMessage);
            }
            return endPoint;
        }

        

    }
}
