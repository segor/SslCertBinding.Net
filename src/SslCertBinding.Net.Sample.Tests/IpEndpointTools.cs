using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace SslCertBinding.Net.Sample.Tests
{
	public static class IpEndpointTools
	{
		public static bool IpEndpointIsAvailableForListening(IPEndPoint ipPort) {
			IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
			IPEndPoint[] tcpEndPointArray = ipGlobalProperties.GetActiveTcpListeners();
			return !tcpEndPointArray.Contains(ipPort);
		}

		public static IPEndPoint ParseIpEndPoint(string str) {
			var ipPort = str.Split(':');
			return new IPEndPoint(IPAddress.Parse(ipPort[0]), int.Parse(ipPort[1]));
		}
	}
}