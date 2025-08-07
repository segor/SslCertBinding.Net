using System;
using System.Net;
using System.Net.Sockets;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    public class BindingEndPointTests
    {
        [TestCase("::", 8080, AddressFamily.InterNetworkV6, true)]
        [TestCase("::1", 8080, AddressFamily.InterNetworkV6, true)]
        [TestCase("2001:db8::1", 443, AddressFamily.InterNetworkV6, true)]
        [TestCase("[2001:db8::1]", 443, AddressFamily.InterNetworkV6, true)]
        [TestCase("sub.domain.example.com", 1234, AddressFamily.Unspecified, false)]
        [TestCase("xn--d1acufc.xn--p1ai", 443, AddressFamily.Unspecified, false)] 
        [TestCase("my-host_name.example-site.co.uk", 8443, AddressFamily.Unspecified, false)]
        [TestCase("localhost", 900, AddressFamily.Unspecified, false)]
        public void ConstructorWithHostAndPortHandlesVariousCases(string host, int port, AddressFamily expectedFamily, bool isIp)
        {
            var ep = new BindingEndPoint(host, port);

            Assert.That(ep.Host, Is.EqualTo(host.Trim('[', ']')));
            Assert.That(ep.Port, Is.EqualTo(port));
            Assert.That(ep.AddressFamily, Is.EqualTo(expectedFamily));
            Assert.That(ep.IsIpEndpoint, Is.EqualTo(isIp));
            if (isIp)
            {
                Assert.That(ep.ToIPEndPoint(), Is.EqualTo(new IPEndPoint(IPAddress.Parse(host), port)));
            }
            else
            {
                Assert.That(() => ep.ToIPEndPoint(), Throws.InvalidOperationException);

                var dnsEndPoint = new DnsEndPoint(host, port);
                Assert.That(ep.ToDnsEndPoint(), Is.EqualTo(dnsEndPoint));
            }
        }

        [TestCase("::1", 8080)]
        [TestCase("::", 80)]
        [TestCase("2001:db8::1", 443)]
        [TestCase("[2001:db8::1]", 443)]
        public void ConstructorWithIPv6AddressAndPortSetsProperties(string ipStr, int port)
        {
            var ip = IPAddress.Parse(ipStr);
            var ep = new BindingEndPoint(ip, port);

            Assert.That(ep.Host, Is.EqualTo(ip.ToString()));
            Assert.That(ep.Port, Is.EqualTo(port));
            Assert.That(ep.AddressFamily, Is.EqualTo(AddressFamily.InterNetworkV6));
            Assert.That(ep.IsIpEndpoint, Is.True);
            Assert.That(ep.ToIPEndPoint(), Is.EqualTo(new IPEndPoint(ip, port)));
        }

        [TestCase("example.com", 443, AddressFamily.Unspecified, false)]
        [TestCase("sub.domain.example.com", 8443, AddressFamily.Unspecified, false)]
        [TestCase("xn--d1acufc.xn--p1ai", 443, AddressFamily.Unspecified, false)]
        [TestCase("127.0.0.1", 8080, AddressFamily.InterNetwork, true)]
        [TestCase("::1", 8080, AddressFamily.InterNetworkV6, true)]
        public void ConstructorWithDnsEndPointSetsProperties(string host, int port, AddressFamily expectedFamily, bool isIp)
        {
            var dnsEndPoint = new DnsEndPoint(host, port);
            var bindingEndPoint = new BindingEndPoint(dnsEndPoint);

            Assert.That(bindingEndPoint.Host, Is.EqualTo(host));
            Assert.That(bindingEndPoint.Port, Is.EqualTo(port));
            Assert.That(bindingEndPoint.AddressFamily, Is.EqualTo(expectedFamily));
            Assert.That(bindingEndPoint.IsIpEndpoint, Is.EqualTo(isIp));
            Assert.That(bindingEndPoint.ToDnsEndPoint(), Is.EqualTo(dnsEndPoint));
        }

        [TestCase("2001:db8::1", 1234, "[2001:db8::1]:1234")]
        [TestCase("::1", 80, "[::1]:80")]
        [TestCase("[::1]", 80, "[::1]:80")]
        [TestCase("::", 800, "[::]:800")]
        [TestCase("my-host.example.com", 443, "my-host.example.com:443")]
        [TestCase("xn--d1acufc.xn--p1ai", 443, "xn--d1acufc.xn--p1ai:443")]
        public void ToStringReturnsExpectedStringForIPv6AndComplexDns(string host, int port, string expected)
        {
            var ep = new BindingEndPoint(host, port);
            Assert.That(ep.ToString(), Is.EqualTo(expected));

            var dnsEp = new BindingEndPoint(new DnsEndPoint(host, port));
            Assert.That(dnsEp.ToString(), Is.EqualTo(expected));
        }

        [TestCase("[2001:db8::1]:443", "2001:db8::1", 443, true)]
        [TestCase("::1:8080", "::1", 8080, true)]
        [TestCase(":::80", "::", 80, true)]
        [TestCase("2001:db8::1:443", "2001:db8::1", 443, true)]
        [TestCase("sub.domain.example.com:1234", "sub.domain.example.com", 1234, false)]
        [TestCase("xn--d1acufc.xn--p1ai:443", "xn--d1acufc.xn--p1ai", 443, false)]
        [TestCase("my-host_name.example-site.co.uk:8443", "my-host_name.example-site.co.uk", 8443, false)]
        public void TryParseValidIPv6AndComplexDnsReturnsTrue(string input, string expectedHost, int expectedPort, bool isIp)
        {
            var result = BindingEndPoint.TryParse(input, out var ep);

            Assert.That(result, Is.True);
            Assert.That(ep.Host, Is.EqualTo(expectedHost));
            Assert.That(ep.Port, Is.EqualTo(expectedPort));
            Assert.That(ep.IsIpEndpoint, Is.EqualTo(isIp));
        }

        [TestCase("[2001:db8::1]", 443)]
        [TestCase("::1", 8080)]
        [TestCase("2001:db8::1", 443)]
        public void EqualsIPEndPointWorksForIPv6(string ipStr, int port)
        {
            var ipEp = new IPEndPoint(IPAddress.Parse(ipStr), port);
            var ep = new BindingEndPoint(ipEp);

            Assert.That(((IEquatable<IPEndPoint>)ep).Equals(ipEp), Is.True);
        }
    }
}
