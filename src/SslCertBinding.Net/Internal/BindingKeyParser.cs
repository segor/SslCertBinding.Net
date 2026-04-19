using System;
using System.Globalization;
using System.Net;

namespace SslCertBinding.Net.Internal
{
#pragma warning disable CA2249 // IndexOf is used for .NET Framework compatibility.
    internal static class BindingKeyParser
    {
        public static bool IsValidPort(int port)
        {
            return port >= IPEndPoint.MinPort && port <= IPEndPoint.MaxPort;
        }

        public static bool TryParseIpPort(string value, out IPAddress address, out int port)
        {
            address = null;
            port = 0;

            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            value = value.Trim();
            string hostPart;
            string portPart;
            if (value[0] == '[')
            {
                int closingBracket = value.IndexOf(']');
                if (closingBracket < 0 || closingBracket + 1 >= value.Length || value[closingBracket + 1] != ':')
                {
                    return false;
                }

                hostPart = value.Substring(1, closingBracket - 1);
                portPart = value.Substring(closingBracket + 2);
            }
            else
            {
                int separatorIndex = value.LastIndexOf(':');
                if (separatorIndex <= 0 || value.IndexOf(':') != separatorIndex)
                {
                    return false;
                }

                hostPart = value.Substring(0, separatorIndex);
                portPart = value.Substring(separatorIndex + 1);
            }

            if (!TryParsePort(portPart, out port))
            {
                return false;
            }

            return IPAddress.TryParse(hostPart, out address);
        }

        public static bool TryParseHostPort(string value, out string host, out int port)
        {
            host = null;
            port = 0;

            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            value = value.Trim();
            int separatorIndex = value.LastIndexOf(':');
            if (separatorIndex <= 0 || separatorIndex == value.Length - 1)
            {
                return false;
            }

            string parsedHost = value.Substring(0, separatorIndex);
            string portPart = value.Substring(separatorIndex + 1);
            if (parsedHost.Length == 0 || parsedHost[0] == '[' || parsedHost.IndexOf(']') >= 0)
            {
                return false;
            }

            if (!TryParsePort(portPart, out int parsedPort) || !IsValidHostname(parsedHost))
            {
                return false;
            }

            host = parsedHost;
            port = parsedPort;
            return true;
        }

        public static bool TryParsePort(string value, out int port)
        {
            return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out port)
                && IsValidPort(port);
        }

        public static bool IsValidHostname(string host)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                return false;
            }

            if (!string.Equals(host, host.Trim(), StringComparison.Ordinal)
                || host.IndexOf(':') >= 0
                || IPAddress.TryParse(host, out _))
            {
                return false;
            }

            int wildcardIndex = host.IndexOf('*');
            if (wildcardIndex >= 0)
            {
                if (!host.StartsWith("*.", StringComparison.Ordinal) || wildcardIndex != 0)
                {
                    return false;
                }

                string wildcardSuffix = host.Substring(2);
                return wildcardSuffix.Length > 0
                    && wildcardSuffix.IndexOf('*') < 0
                    && Uri.CheckHostName(wildcardSuffix) == UriHostNameType.Dns;
            }

            return Uri.CheckHostName(host) == UriHostNameType.Dns;
        }

        public static string RequireValidHostname(string host, string paramName)
        {
            if (!IsValidHostname(host))
            {
                throw new ArgumentException(
                    string.IsNullOrWhiteSpace(host) ? "Value cannot be null or empty." : "Hostname must be a valid DNS name.",
                    paramName);
            }

            return host;
        }
    }
#pragma warning restore CA2249 // IndexOf is used for .NET Framework compatibility.
}
