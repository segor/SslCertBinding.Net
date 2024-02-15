using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace SslCertBinding.Net.Tests
{
    public static class IpEndpointTools
    {
        public static bool IpEndpointIsAvailableForListening(IPEndPoint ipPort)
        {
            IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] tcpEndPointArray = ipGlobalProperties.GetActiveTcpListeners();
            return !tcpEndPointArray.Contains(ipPort);
        }

        public static IPEndPoint ParseIpEndPoint(string str)
        {
            int portSeparatorIndex = str.LastIndexOf(':');
            string ip = str.Substring(0, portSeparatorIndex);
            string port = str.Substring(portSeparatorIndex + 1);
            return new IPEndPoint(IPAddress.Parse(ip), int.Parse(port, CultureInfo.InvariantCulture));
        }
    }
}
