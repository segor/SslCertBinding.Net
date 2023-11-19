using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace SslCertBinding.Net.Tests
{
	public static class IpEndpointTools
	{
		public static bool IpEndpointIsAvailableForListening(IPEndPoint ipPort) {
			IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
			IPEndPoint[] tcpEndPointArray = ipGlobalProperties.GetActiveTcpListeners();
			return !tcpEndPointArray.Contains(ipPort);
		}

		public static IPEndPoint ParseIpEndPoint(string str) {
			var portSeparatorIndex = str.LastIndexOf(':');
			var ip = str.Substring(0, portSeparatorIndex);
			var port = str.Substring(portSeparatorIndex + 1);
			return new IPEndPoint(IPAddress.Parse(ip), int.Parse(port));
		}
	}
}