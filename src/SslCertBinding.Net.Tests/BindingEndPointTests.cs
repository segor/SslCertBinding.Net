using System;
using System.Net;
using System.Net.Sockets;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    /// <summary>
    /// Unit tests for <see cref="BindingEndPoint"/>.
    /// </summary>
    [TestFixture]
    public class BindingEndPointTests
    {
        #region Constructors

        /// <summary>
        /// Tests that the string constructor handles both IPv4/IPv6 addresses and hostnames.
        /// Verifies correct parsing, address family detection, and IP vs. DNS endpoint distinction.
        /// </summary>
        [TestCase("::", 8080, AddressFamily.InterNetworkV6, true)]
        [TestCase("::1", 8080, AddressFamily.InterNetworkV6, true)]
        [TestCase("2001:db8::1", 443, AddressFamily.InterNetworkV6, true)]
        [TestCase("[2001:db8::1]", 443, AddressFamily.InterNetworkV6, true)]
        [TestCase("sub.domain.example.com", 1234, AddressFamily.Unspecified, false)]
        [TestCase("Sub.Domain.Example.Com", 1234, AddressFamily.Unspecified, false)]
        [TestCase("SUB.DOMAIN.EXAMPLE.COM", 1234, AddressFamily.Unspecified, false)]
        [TestCase("xn--d1acufc.xn--p1ai", 443, AddressFamily.Unspecified, false)] 
        [TestCase("XN--D1ACUFC.XN--P1AI", 443, AddressFamily.Unspecified, false)]
        [TestCase("my-host_name.example-site.co.uk", 8443, AddressFamily.Unspecified, false)]
        [TestCase("MY-HOST_NAME.EXAMPLE-SITE.CO.UK", 8443, AddressFamily.Unspecified, false)]
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
                Assert.That(() => ep.ToIPEndPoint(), Throws.TypeOf<InvalidCastException>());

                var dnsEndPoint = new DnsEndPoint(host, port);
                Assert.That(ep.ToDnsEndPoint(), Is.EqualTo(dnsEndPoint));
            }
        }

        /// <summary>
        /// Tests that the IPAddress constructor correctly initializes properties for both IPv4 and IPv6 addresses.
        /// Verifies host normalization, port assignment, address family detection, and endpoint conversion.
        /// </summary>
        [TestCase("127.0.0.1", 8080, AddressFamily.InterNetwork)]
        [TestCase("192.168.0.1", 443, AddressFamily.InterNetwork)]
        [TestCase("::1", 8080, AddressFamily.InterNetworkV6)]
        [TestCase("::", 80, AddressFamily.InterNetworkV6)]
        [TestCase("2001:db8::1", 443, AddressFamily.InterNetworkV6)]
        public void ConstructorWithIPAddressAndPortSetsProperties(string ipStr, int port, AddressFamily expectedFamily)
        {
            var ip = IPAddress.Parse(ipStr);
            var ep = new BindingEndPoint(ip, port);

            Assert.That(ep.Host, Is.EqualTo(ip.ToString()));
            Assert.That(ep.Port, Is.EqualTo(port));
            Assert.That(ep.AddressFamily, Is.EqualTo(expectedFamily));
            Assert.That(ep.IsIpEndpoint, Is.True);
            Assert.That(ep.ToIPEndPoint(), Is.EqualTo(new IPEndPoint(ip, port)));
        }

        /// <summary>
        /// Tests that the DnsEndPoint constructor correctly parses hostnames and IP addresses,
        /// distinguishing between IP-based and DNS-based endpoints.
        /// </summary>
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

        #endregion

        #region ToString() Tests

        /// <summary>
        /// Tests that ToString() produces correctly formatted output for IPv4, IPv6 (bracketed),
        /// and hostname endpoints with ports. Verifies IPv6 addresses are bracketed and IPv4/DNS are unbracketed.
        /// </summary>
        [TestCase("127.0.0.1", 8080, "127.0.0.1:8080")]
        [TestCase("192.168.0.1", 443, "192.168.0.1:443")]
        [TestCase("2001:db8::1", 1234, "[2001:db8::1]:1234")]
        [TestCase("::1", 80, "[::1]:80")]
        [TestCase("[::1]", 80, "[::1]:80")]
        [TestCase("::", 800, "[::]:800")]
        [TestCase("my-host.example.com", 443, "my-host.example.com:443")]
        [TestCase("My-Host.Example.Com", 443, "My-Host.Example.Com:443")]
        [TestCase("MY-HOST.EXAMPLE.COM", 443, "MY-HOST.EXAMPLE.COM:443")]
        [TestCase("xn--d1acufc.xn--p1ai", 443, "xn--d1acufc.xn--p1ai:443")]
        [TestCase("XN--D1ACUFC.XN--P1AI", 443, "XN--D1ACUFC.XN--P1AI:443")]
        public void ToStringReturnsExpectedStringForIPv4IPv6AndComplexDns(string host, int port, string expected)
        {
            var ep = new BindingEndPoint(host, port);
            Assert.That(ep.ToString(), Is.EqualTo(expected));

            var dnsEp = new BindingEndPoint(new DnsEndPoint(host, port));
            Assert.That(dnsEp.ToString(), Is.EqualTo(expected));
        }

        #endregion

        #region TryParse(string) Tests

        /// <summary>
        /// Tests that TryParse correctly parses valid IPv4, IPv6 (bracketed and unbracketed),
        /// and hostname endpoint strings with ports. Validates correct endpoint type detection (IP vs. DNS).
        /// </summary>
        [TestCase("127.0.0.1:80", "127.0.0.1", 80, true)]
        [TestCase("192.168.1.1:8080", "192.168.1.1", 8080, true)]
        [TestCase("[2001:db8::1]:443", "2001:db8::1", 443, true)]
        [TestCase("::1:8080", "::1", 8080, true)]
        [TestCase(":::80", "::", 80, true)]
        [TestCase("2001:db8::1:443", "2001:db8::1", 443, true)]
        [TestCase("sub.domain.example.com:1234", "sub.domain.example.com", 1234, false)]
        [TestCase("Sub.Domain.Example.Com:1234", "Sub.Domain.Example.Com", 1234, false)]
        [TestCase("SUB.DOMAIN.EXAMPLE.COM:1234", "SUB.DOMAIN.EXAMPLE.COM", 1234, false)]
        [TestCase("xn--d1acufc.xn--p1ai:443", "xn--d1acufc.xn--p1ai", 443, false)]
        [TestCase("XN--D1ACUFC.XN--P1AI:443", "XN--D1ACUFC.XN--P1AI", 443, false)]
        [TestCase("my-host_name.example-site.co.uk:8443", "my-host_name.example-site.co.uk", 8443, false)]
        [TestCase("MY-HOST_NAME.EXAMPLE-SITE.CO.UK:8443", "MY-HOST_NAME.EXAMPLE-SITE.CO.UK", 8443, false)]
        public void TryParseValidIPv4IPv6AndComplexDnsReturnsTrue(string input, string expectedHost, int expectedPort, bool isIp)
        {
            var result = BindingEndPoint.TryParse(input, out var ep);

            Assert.That(result, Is.True);
            Assert.That(ep.Host, Is.EqualTo(expectedHost));
            Assert.That(ep.Port, Is.EqualTo(expectedPort));
            Assert.That(ep.IsIpEndpoint, Is.EqualTo(isIp));
        }

        /// <summary>
        /// Tests that TryParse correctly rejects invalid port ranges (negative or > 65535).
        /// </summary>
        [TestCase("127.0.0.1:-1")]
        [TestCase("example.com:65536")]
        [TestCase("::1:99999")]
        public void TryParseReturnsFalseForInvalidPorts(string input)
        {
            var result = BindingEndPoint.TryParse(input, out _);
            Assert.That(result, Is.False, $"TryParse should fail for invalid port in: {input}");
        }

        /// <summary>
        /// Tests that TryParse correctly rejects malformed inputs
        /// (empty, missing host, missing port, non-numeric port, etc.).
        /// </summary>
        [TestCase("")]
        [TestCase("   ")]
        [TestCase("localhost")]  // No port separator
        [TestCase(":80")]  // No host
        [TestCase("example.com:")]  // No port
        [TestCase("example.com:abc")]  // Non-numeric port
        public void TryParseReturnsFalseForMalformedInputs(string input)
        {
            var result = BindingEndPoint.TryParse(input, out _);
            Assert.That(result, Is.False, $"TryParse should fail for malformed input: '{input}'");
        }

        #endregion

        #region Parse(string) Tests

        /// <summary>
        /// Tests that Parse throws FormatException for invalid input.
        /// </summary>
        [TestCase("localhost")]  // No port
        [TestCase(":80")]  // No host
        public void ParseThrowsFormatExceptionForInvalidInput(string input)
        {
            Assert.That(() => BindingEndPoint.Parse(input), Throws.TypeOf<FormatException>());
        }

        /// <summary>
        /// Tests that Parse correctly handles roundtrips: Parse(ToString()) equals the original endpoint.
        /// Validates IPv4, IPv6 (bracketed and unbracketed), and hostname endpoints.
        /// </summary>
        [TestCase("127.0.0.1", 80)]
        [TestCase("::1", 443)]
        [TestCase("[2001:db8::1]", 8080)]
        [TestCase("example.com", 443)]
        public void RoundtripParseToStringParse(string host, int port)
        {
            var original = new BindingEndPoint(host, port);
            var stringForm = original.ToString();
            var parsed = BindingEndPoint.Parse(stringForm);

            Assert.That(parsed, Is.EqualTo(original), $"Roundtrip failed: {stringForm}");
            Assert.That(parsed.Host, Is.EqualTo(original.Host));
            Assert.That(parsed.Port, Is.EqualTo(original.Port));
        }

        #endregion

        #region Equality & GetHashCode() Tests

        /// <summary>
        /// Tests that IPv4 endpoints created via different constructor paths are equal
        /// and produce equal hash codes. Validates consistency across string, IPAddress, and IPEndPoint constructors.
        /// </summary>
        [TestCase("127.0.0.1", 80)]
        [TestCase("192.168.1.1", 443)]
        [TestCase("0.0.0.0", 8080)]
        public void EqualityAndHashCodeConsistentAcrossConstructorPathsIPv4(string ipStr, int port)
        {
            var ipAddr = IPAddress.Parse(ipStr);
            var ep1 = new BindingEndPoint(ipStr, port);
            var ep2 = new BindingEndPoint(ipAddr, port);
            var ep3 = new BindingEndPoint(new IPEndPoint(ipAddr, port));

            Assert.That(ep1, Is.EqualTo(ep2), "String constructor should equal IPAddress constructor");
            Assert.That(ep2, Is.EqualTo(ep3), "IPAddress constructor should equal IPEndPoint constructor");
            Assert.That(ep1.GetHashCode(), Is.EqualTo(ep2.GetHashCode()), "Hash codes should match for equal endpoints");
            Assert.That(ep2.GetHashCode(), Is.EqualTo(ep3.GetHashCode()), "Hash codes should match for equal endpoints");
        }

        /// <summary>
        /// Tests that IPv6 endpoints created via different constructor paths are equal
        /// and produce equal hash codes. Validates consistency across string, IPAddress, and IPEndPoint constructors.
        /// </summary>
        [TestCase("::1", 80)]
        [TestCase("2001:db8::1", 443)]
        [TestCase("::", 8080)]
        public void EqualityAndHashCodeConsistentAcrossConstructorPathsIPv6(string ipStr, int port)
        {
            var ipAddr = IPAddress.Parse(ipStr);
            var ep1 = new BindingEndPoint(ipStr, port);
            var ep2 = new BindingEndPoint(ipAddr, port);
            var ep3 = new BindingEndPoint(new IPEndPoint(ipAddr, port));

            Assert.That(ep1, Is.EqualTo(ep2), "String constructor should equal IPAddress constructor");
            Assert.That(ep2, Is.EqualTo(ep3), "IPAddress constructor should equal IPEndPoint constructor");
            Assert.That(ep1.GetHashCode(), Is.EqualTo(ep2.GetHashCode()), "Hash codes should match for equal endpoints");
            Assert.That(ep2.GetHashCode(), Is.EqualTo(ep3.GetHashCode()), "Hash codes should match for equal endpoints");
        }

        /// <summary>
        /// Tests Equals(IPEndPoint) for IP-based endpoints. Verifies that an IP-based BindingEndPoint
        /// correctly equals the underlying IPEndPoint.
        /// </summary>
        [TestCase("[2001:db8::1]", 443)]
        [TestCase("::1", 8080)]
        [TestCase("2001:db8::1", 443)]
        public void EqualsIPEndPointWorksForIPv6(string ipStr, int port)
        {
            var ipEp = new IPEndPoint(IPAddress.Parse(ipStr), port);
            var ep = new BindingEndPoint(ipEp);

            Assert.That(((IEquatable<IPEndPoint>)ep).Equals(ipEp), Is.True);
            Assert.That(ep.GetHashCode(), Is.EqualTo(ipEp.GetHashCode()), "Hash codes should match for equal endpoints");
        }

        /// <summary>
        /// Tests Equals(DnsEndPoint) for DNS-based endpoints. Verifies that a DNS-based BindingEndPoint
        /// correctly equals the underlying DnsEndPoint, with the same hostname comparison.
        /// </summary>
        [TestCase("example.com", 443)]
        [TestCase("my-host.local", 8080)]
        [TestCase("Example.Com", 443)]  // Different case should be equal
        [TestCase("EXAMPLE.COM", 443)]  // Uppercase should be equal
        [TestCase("MY-HOST.LOCAL", 8080)]  // Uppercase should be equal
        public void EqualsDnsEndPointWorks(string host, int port)
        {
            var dnsEp = new DnsEndPoint(host, port);
            var bindingEp = new BindingEndPoint(host, port);

            Assert.That(bindingEp.Equals(dnsEp), Is.True, "BindingEndPoint should equal DnsEndPoint");
            Assert.That(bindingEp.GetHashCode(), Is.EqualTo(dnsEp.GetHashCode()), "Hash codes should match for equal endpoints");
        }

        /// <summary>
        /// Tests that DNS-based and IP-based BindingEndPoints are not equal.
        /// Documents the intentional asymmetry: a DNS endpoint should never equal an IP endpoint.
        /// </summary>
        [TestCase("example.com", 443)]
        public void DnsNotEqualsIpEndpoint(string host, int port)
        {
            var dns = new BindingEndPoint(host, port);
            var ip = new BindingEndPoint(IPAddress.Loopback, port);

            Assert.That(dns.Equals((object)ip), Is.False);
            Assert.That(dns.Equals(ip), Is.False);
            // Hash codes should differ for unequal endpoints
            Assert.That(dns.GetHashCode(), Is.Not.EqualTo(ip.GetHashCode()), "Hash codes should differ for unequal endpoints");
        }

        /// <summary>
        /// Tests that BindingEndPoint hostname equality is case-insensitive in .NET 5+.
        /// Verifies that endpoints with different case but same hostname are expected equality that follows the framework-native DnsEndPoint equality semantics.
        /// </summary>
        [TestCase("example.com", "Example.Com", 443)]
        [TestCase("example.com", "EXAMPLE.COM", 443)]
        [TestCase("my-host.example.local", "MY-HOST.EXAMPLE.LOCAL", 8080)]
        [TestCase("Sub.Domain.Example.Com", "sub.domain.example.com", 1234)]
        public void BindingEndPointHostnameEqualityIsCaseInsensitive(string host1, string host2, int port)
        {
            var ep1 = new BindingEndPoint(host1, port);
            var ep2 = new BindingEndPoint(host2, port);

            // Expected equality follows the framework-native DnsEndPoint equality semantics.
            var expectedeEquality = new DnsEndPoint(host1, port).Equals(new DnsEndPoint(host2, port));
            Assert.That(ep1.Equals(ep2), Is.EqualTo(expectedeEquality), $"Equality should match DnsEndPoint.Equals for {host1} vs {host2}");

            if (expectedeEquality)
            {
                Assert.That(ep1.GetHashCode(), Is.EqualTo(ep2.GetHashCode()), "Hash codes should match when endpoints are equal");
            } 
        }

        /// <summary>
        /// Tests that Equals(object) returns false when compared with non-endpoint types
        /// (strings, numbers, null, etc.). Verifies hash code consistency.
        /// </summary>
        [Test]
        public void EqualsObjectReturnsFalseForNonEndpointTypes()
        {
            var ep = new BindingEndPoint("example.com", 443);

            Assert.That(ep.Equals((object)"example.com:443"), Is.False);
            Assert.That(ep.Equals((object)443), Is.False);
            Assert.That(ep.Equals((object)null), Is.False);
            // Hash code should be consistent regardless of failed equality checks
            var hashCode = ep.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo("example.com:443".GetHashCode()), "Hash codes should differ for different types");
        }

        #endregion

        #region Implicit Operator Tests

        /// <summary>
        /// Tests that implicit conversion from IPEndPoint to BindingEndPoint works correctly
        /// for both IPv4 and IPv6 addresses.
        /// </summary>
        [TestCase("127.0.0.1", 80)]
        [TestCase("::1", 443)]
        public void ImplicitConversionFromIPEndPoint(string ipStr, int port)
        {
            var ipAddr = IPAddress.Parse(ipStr);
            var ipEp = new IPEndPoint(ipAddr, port);
            BindingEndPoint bindingEp = ipEp;

            Assert.That(bindingEp, Is.Not.Null);
            Assert.That(bindingEp.Port, Is.EqualTo(port));
        }

        /// <summary>
        /// Tests that implicit conversion from DnsEndPoint to BindingEndPoint works correctly
        /// for both hostnames and IP address strings.
        /// </summary>
        [TestCase("example.com", 443)]
        [TestCase("127.0.0.1", 80)]
        public void ImplicitConversionFromDnsEndPoint(string host, int port)
        {
            var dnsEp = new DnsEndPoint(host, port);
            BindingEndPoint bindingEp = dnsEp;

            Assert.That(bindingEp, Is.Not.Null);
            Assert.That(bindingEp.Host, Is.EqualTo(host));
            Assert.That(bindingEp.Port, Is.EqualTo(port));
        }

        /// <summary>
        /// Tests that implicit conversion from null IPEndPoint or DnsEndPoint returns null.
        /// </summary>
        [Test]
        public void ImplicitConversionFromNullReturnsNull()
        {
            IPEndPoint nullIpEp = null;
            DnsEndPoint nullDnsEp = null;

            BindingEndPoint bindingEpFromIp = nullIpEp;
            BindingEndPoint bindingEpFromDns = nullDnsEp;

            Assert.That(bindingEpFromIp, Is.Null);
            Assert.That(bindingEpFromDns, Is.Null);
        }

        #endregion
    }
}
