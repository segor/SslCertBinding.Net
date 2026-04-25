using System;
using System.Net;
using NUnit.Framework;

#nullable disable
namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    public class SslBindingKeyTests
    {
        [Test]
        public void IpPortKeyRoundTripsWithIPEndPoint()
        {
            var endPoint = new IPEndPoint(IPAddress.Parse("0.0.0.0"), 443);
            var key = new IpPortKey(endPoint);

            Assert.Multiple(() =>
            {
                Assert.That(key.Address, Is.EqualTo(endPoint.Address));
                Assert.That(key.Port, Is.EqualTo(endPoint.Port));
                Assert.That(key.ToIPEndPoint(), Is.EqualTo(endPoint));
                Assert.That((IPEndPoint)key, Is.EqualTo(endPoint));
            });
        }

        [Test]
        public void IpEndPointToIpPortKeyReturnsIpPortKey()
        {
            var endPoint = new IPEndPoint(IPAddress.Parse("0.0.0.0"), 443);

            IpPortKey key = endPoint.ToIpPortKey();

            Assert.Multiple(() =>
            {
                Assert.That(key.Address, Is.EqualTo(endPoint.Address));
                Assert.That(key.Port, Is.EqualTo(endPoint.Port));
            });
        }

        [Test]
        public void IpPortKeyParseSupportsBracketedIpv6()
        {
            IpPortKey key = IpPortKey.Parse("[2001:db8::1]:443");

            Assert.Multiple(() =>
            {
                Assert.That(key.Address, Is.EqualTo(IPAddress.Parse("2001:db8::1")));
                Assert.That(key.Port, Is.EqualTo(443));
                Assert.That(key.ToString(), Is.EqualTo("[2001:db8::1]:443"));
            });
        }

        [Test]
        public void HostnamePortKeyRoundTripsWithDnsEndPoint()
        {
            var endPoint = new DnsEndPoint("www.contoso.com", 443);
            var key = new HostnamePortKey(endPoint);

            Assert.Multiple(() =>
            {
                Assert.That(key.Hostname, Is.EqualTo("www.contoso.com"));
                Assert.That(key.Port, Is.EqualTo(443));
                Assert.That(key.ToDnsEndPoint(), Is.EqualTo(endPoint));
                Assert.That((DnsEndPoint)key, Is.EqualTo(endPoint));
            });
        }

        [Test]
        public void DnsEndPointToHostnamePortKeyReturnsHostnamePortKey()
        {
            var endPoint = new DnsEndPoint("www.contoso.com", 443);

            HostnamePortKey key = endPoint.ToHostnamePortKey();

            Assert.Multiple(() =>
            {
                Assert.That(key.Hostname, Is.EqualTo(endPoint.Host));
                Assert.That(key.Port, Is.EqualTo(endPoint.Port));
            });
        }

        [Test]
        public void DnsEndPointToScopedCcsKeyReturnsScopedCcsKey()
        {
            var endPoint = new DnsEndPoint("www.contoso.com", 443);

            ScopedCcsKey key = endPoint.ToScopedCcsKey();

            Assert.Multiple(() =>
            {
                Assert.That(key.Hostname, Is.EqualTo(endPoint.Host));
                Assert.That(key.Port, Is.EqualTo(endPoint.Port));
            });
        }

        [Test]
        public void HostnamePortKeyRejectsIpAddressHost()
        {
            void Constructor()
            {
                _ = new HostnamePortKey("127.0.0.1", 443);
            }

            ArgumentException ex = Assert.Throws<ArgumentException>(Constructor);
            Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
        }

        [Test]
        public void GenericParseRequiresExplicitBindingKind()
        {
            SslBindingKey key = SslBindingKey.Parse("localhost:443", SslBindingKind.HostnamePort);

            Assert.That(key, Is.TypeOf<HostnamePortKey>());
        }

        [Test]
        public void GenericParseSupportsCcsBindingKind()
        {
            SslBindingKey key = SslBindingKey.Parse("443", SslBindingKind.CcsPort);

            Assert.Multiple(() =>
            {
                Assert.That(key, Is.TypeOf<CcsPortKey>());
                Assert.That(((CcsPortKey)key).Port, Is.EqualTo(443));
            });
        }

        [Test]
        public void GenericParseSupportsScopedCcsBindingKind()
        {
            SslBindingKey key = SslBindingKey.Parse("www.contoso.com:443", SslBindingKind.ScopedCcs);

            Assert.Multiple(() =>
            {
                Assert.That(key, Is.TypeOf<ScopedCcsKey>());
                Assert.That(((ScopedCcsKey)key).Hostname, Is.EqualTo("www.contoso.com"));
                Assert.That(((ScopedCcsKey)key).Port, Is.EqualTo(443));
            });
        }

        [Test]
        public void GenericTryParseReturnsFalseForMismatchedKind()
        {
            bool result = SslBindingKey.TryParse("localhost:443", SslBindingKind.IpPort, out SslBindingKey key);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.False);
                Assert.That(key, Is.Null);
            });
        }

        [Test]
        public void GenericTryParseReturnsFalseForMismatchedCcsKind()
        {
            bool result = SslBindingKey.TryParse("localhost:443", SslBindingKind.CcsPort, out SslBindingKey key);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.False);
                Assert.That(key, Is.Null);
            });
        }

        [Test]
        public void GenericTryParseReturnsFalseForMismatchedScopedCcsKind()
        {
            bool result = SslBindingKey.TryParse("127.0.0.1:443", SslBindingKind.ScopedCcs, out SslBindingKey key);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.False);
                Assert.That(key, Is.Null);
            });
        }
    }
}
