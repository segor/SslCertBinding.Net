using System;
using System.Net;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    public class SslBindingKeyContractTests
    {
        [Test]
        public void GenericParseRejectsUnknownBindingKind()
        {
            ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => SslBindingKey.Parse("ignored", (SslBindingKind)999));
            Assert.That(ex.ParamName, Is.EqualTo("kind"));
        }

        [Test]
        public void GenericTryParseRejectsUnknownBindingKind()
        {
            ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => SslBindingKey.TryParse("ignored", (SslBindingKind)999, out _));
            Assert.That(ex.ParamName, Is.EqualTo("kind"));
        }

        [Test]
        public void GenericTryParseSupportsHostnameKind()
        {
            bool result = SslBindingKey.TryParse("www.contoso.com:443", SslBindingKind.HostnamePort, out SslBindingKey? key);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.True);
                Assert.That(key, Is.Not.Null);
                Assert.That(key, Is.TypeOf<HostnamePortKey>());
            });
        }

        [Test]
        public void GenericTryParseSupportsIpKind()
        {
            bool result = SslBindingKey.TryParse("127.0.0.1:443", SslBindingKind.IpPort, out SslBindingKey? key);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.True);
                Assert.That(key, Is.Not.Null);
                Assert.That(key, Is.TypeOf<IpPortKey>());
            });
        }

        [Test]
        public void GenericTryParseSupportsCcsKind()
        {
            bool result = SslBindingKey.TryParse("443", SslBindingKind.CcsPort, out SslBindingKey? key);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.True);
                Assert.That(key, Is.Not.Null);
                Assert.That(key, Is.TypeOf<CcsPortKey>());
            });
        }

        [Test]
        public void GenericTryParseSupportsScopedCcsKind()
        {
            bool result = SslBindingKey.TryParse("www.contoso.com:443", SslBindingKind.ScopedCcs, out SslBindingKey? key);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.True);
                Assert.That(key, Is.Not.Null);
                Assert.That(key, Is.TypeOf<ScopedCcsKey>());
            });
        }

        [Test]
        public void GenericTryParseReturnsFalseForInvalidHostnameValue()
        {
            bool result = SslBindingKey.TryParse("localhost", SslBindingKind.HostnamePort, out SslBindingKey? key);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.False);
                Assert.That(key, Is.Null);
            });
        }

        [Test]
        public void IpPortKeyFromAndImplicitConversionRoundTrip()
        {
            var endPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8443);

            IpPortKey key = IpPortKey.From(endPoint);
            IpPortKey? implicitKey = endPoint;

            Assert.Multiple(() =>
            {
                Assert.That(implicitKey, Is.Not.Null);
                Assert.That(key.Equals(endPoint), Is.True);
                Assert.That(key.Equals((object)endPoint), Is.True);
                Assert.That(key.Equals(implicitKey), Is.True);
                Assert.That(key.GetHashCode(), Is.EqualTo(implicitKey!.GetHashCode()));
            });
        }

        [Test]
        public void IpPortKeyParseRejectsInvalidValue()
        {
            Assert.Multiple(() =>
            {
                Assert.That(IpPortKey.TryParse("localhost:443", out IpPortKey? key), Is.False);
                Assert.That(key, Is.Null);
                Assert.That(() => IpPortKey.Parse("localhost:443"), Throws.TypeOf<FormatException>());
            });
        }

        [Test]
        public void IpPortKeyParseRejectsNullValue()
        {
            string? value = null;

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => IpPortKey.Parse(value!));
            Assert.That(ex.ParamName, Is.EqualTo("value"));
        }

        [Test]
        public void IpPortKeyObjectEqualityRejectsUnsupportedType()
        {
            var key = new IpPortKey(IPAddress.Any, 443);

            Assert.That(key.Equals("0.0.0.0:443"), Is.False);
        }

        [Test]
        public void IpPortKeyTypedEqualityRejectsNullValues()
        {
            var key = new IpPortKey(IPAddress.Any, 443);
            IpPortKey? otherKey = null;
            IPEndPoint? endPoint = null;

            Assert.Multiple(() =>
            {
                Assert.That(key.Equals(otherKey), Is.False);
                Assert.That(key.Equals(endPoint), Is.False);
            });
        }

        [Test]
        public void IpPortKeyNullImplicitConversionReturnsNullEndPoint()
        {
            IpPortKey? key = null;
            IPEndPoint? endPoint = key;

            Assert.That(endPoint, Is.Null);
        }

        [Test]
        public void HostnamePortKeyFromAndImplicitConversionRoundTrip()
        {
            var endPoint = new DnsEndPoint("www.contoso.com", 8443);

            HostnamePortKey key = HostnamePortKey.From(endPoint);
            HostnamePortKey? implicitKey = endPoint;

            Assert.Multiple(() =>
            {
                Assert.That(implicitKey, Is.Not.Null);
                Assert.That(key.Equals(endPoint), Is.True);
                Assert.That(key.Equals((object)endPoint), Is.True);
                Assert.That(key.Equals(implicitKey), Is.True);
                Assert.That(key.GetHashCode(), Is.EqualTo(implicitKey!.GetHashCode()));
            });
        }

        [Test]
        public void HostnamePortKeyEqualityIgnoresHostCase()
        {
            var left = new HostnamePortKey("WWW.Contoso.Com", 443);
            var right = new HostnamePortKey("www.contoso.com", 443);

            Assert.Multiple(() =>
            {
                Assert.That(left.Equals(right), Is.True);
                Assert.That(left.Equals((object)right), Is.True);
                Assert.That(left.GetHashCode(), Is.EqualTo(right.GetHashCode()));
            });
        }

        [Test]
        public void HostnamePortKeyConstructorPreservesHostname()
        {
            var key = new HostnamePortKey(new DnsEndPoint("www.contoso.com", 443));

            Assert.Multiple(() =>
            {
                Assert.That(key.Hostname, Is.EqualTo("www.contoso.com"));
                Assert.That(key.ToDnsEndPoint().Host, Is.EqualTo("www.contoso.com"));
            });
        }

        [Test]
        public void HostnamePortKeySupportsWildcardHostname()
        {
            var key = new HostnamePortKey("*.example.com", 443);

            Assert.Multiple(() =>
            {
                Assert.That(key.Hostname, Is.EqualTo("*.example.com"));
                Assert.That(key.ToString(), Is.EqualTo("*.example.com:443"));
            });
        }

        [Test]
        public void HostnamePortKeyConstructorRejectsHostnameWhitespaceFormatting()
        {
            var endPoint = new DnsEndPoint(" www.contoso.com ", 443);

            ArgumentException ex = Assert.Throws<ArgumentException>(() => new HostnamePortKey(endPoint));
            Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
        }

        [Test]
        public void HostnamePortKeyParseRejectsInvalidValue()
        {
            Assert.Multiple(() =>
            {
                Assert.That(HostnamePortKey.TryParse("127.0.0.1:443", out HostnamePortKey? key), Is.False);
                Assert.That(key, Is.Null);
                Assert.That(() => HostnamePortKey.Parse("127.0.0.1:443"), Throws.TypeOf<FormatException>());
            });
        }

        [Test]
        public void HostnamePortKeyParseRejectsNullValue()
        {
            string? value = null;

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => HostnamePortKey.Parse(value!));
            Assert.That(ex.ParamName, Is.EqualTo("value"));
        }

        [Test]
        public void HostnamePortKeyTryParseReturnsFalseForMalformedValue()
        {
            bool result = HostnamePortKey.TryParse("localhost", out HostnamePortKey? key);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.False);
                Assert.That(key, Is.Null);
            });
        }

        [Test]
        public void HostnamePortKeyConstructorRejectsNullDnsEndPoint()
        {
            DnsEndPoint? endPoint = null;

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => new HostnamePortKey(endPoint!));
            Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
        }

        [Test]
        public void HostnamePortKeyConstructorRejectsNullHostname()
        {
            string? hostname = null;

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => new HostnamePortKey(hostname!, 443));
            Assert.That(ex.ParamName, Is.EqualTo("hostname"));
        }

        [Test]
        public void HostnamePortKeyObjectEqualityRejectsUnsupportedType()
        {
            var key = new HostnamePortKey("www.contoso.com", 443);

            Assert.That(key.Equals("www.contoso.com:443"), Is.False);
        }

        [Test]
        public void HostnamePortKeyTypedEqualityRejectsNullValues()
        {
            var key = new HostnamePortKey("www.contoso.com", 443);
            HostnamePortKey? otherKey = null;
            DnsEndPoint? endPoint = null;

            Assert.Multiple(() =>
            {
                Assert.That(key.Equals(otherKey), Is.False);
                Assert.That(key.Equals(endPoint), Is.False);
            });
        }

        [Test]
        public void HostnamePortKeyNullImplicitConversionReturnsNullEndPoint()
        {
            HostnamePortKey? key = null;
            DnsEndPoint? endPoint = key;

            Assert.That(endPoint, Is.Null);
        }

        [Test]
        public void CcsPortKeyFromReturnsParsedPort()
        {
            CcsPortKey key = CcsPortKey.From(443);

            Assert.That(key.Port, Is.EqualTo(443));
        }

        [Test]
        public void CcsPortKeyParseRejectsInvalidValue()
        {
            Assert.Multiple(() =>
            {
                Assert.That(CcsPortKey.TryParse("localhost:443", out CcsPortKey? key), Is.False);
                Assert.That(key, Is.Null);
                Assert.That(() => CcsPortKey.Parse("localhost:443"), Throws.TypeOf<FormatException>());
            });
        }

        [Test]
        public void CcsPortKeyParseRejectsNullValue()
        {
            string? value = null;

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => CcsPortKey.Parse(value!));
            Assert.That(ex.ParamName, Is.EqualTo("value"));
        }

        [Test]
        public void CcsPortKeyParseReturnsParsedKey()
        {
            CcsPortKey key = CcsPortKey.Parse("443");

            Assert.Multiple(() =>
            {
                Assert.That(key.Port, Is.EqualTo(443));
                Assert.That(key.ToString(), Is.EqualTo("443"));
            });
        }

        [Test]
        public void CcsPortKeyConstructorRejectsInvalidPort()
        {
            ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => new CcsPortKey(-1));
            Assert.That(ex.ParamName, Is.EqualTo("port"));
        }

        [Test]
        public void CcsPortKeyEqualityUsesPort()
        {
            var left = new CcsPortKey(443);
            var right = new CcsPortKey(443);

            Assert.Multiple(() =>
            {
                Assert.That(left.Equals(right), Is.True);
                Assert.That(left.Equals((object)right), Is.True);
                Assert.That(left.GetHashCode(), Is.EqualTo(right.GetHashCode()));
                Assert.That(left.ToString(), Is.EqualTo("443"));
            });
        }

        [Test]
        public void ScopedCcsKeyFromAndImplicitConversionRoundTrip()
        {
            var endPoint = new DnsEndPoint("www.contoso.com", 8443);

            ScopedCcsKey key = ScopedCcsKey.From(endPoint);
            ScopedCcsKey? implicitKey = endPoint;

            Assert.Multiple(() =>
            {
                Assert.That(implicitKey, Is.Not.Null);
                Assert.That(key.Equals(endPoint), Is.True);
                Assert.That(key.Equals((object)endPoint), Is.True);
                Assert.That(key.Equals(implicitKey), Is.True);
                Assert.That(key.GetHashCode(), Is.EqualTo(implicitKey!.GetHashCode()));
            });
        }

        [Test]
        public void ScopedCcsKeyEqualityIgnoresHostCase()
        {
            var left = new ScopedCcsKey("WWW.Contoso.Com", 443);
            var right = new ScopedCcsKey("www.contoso.com", 443);

            Assert.Multiple(() =>
            {
                Assert.That(left.Equals(right), Is.True);
                Assert.That(left.Equals((object)right), Is.True);
                Assert.That(left.GetHashCode(), Is.EqualTo(right.GetHashCode()));
            });
        }

        [Test]
        public void ScopedCcsKeyConstructorPreservesHostname()
        {
            var key = new ScopedCcsKey(new DnsEndPoint("www.contoso.com", 443));

            Assert.Multiple(() =>
            {
                Assert.That(key.Hostname, Is.EqualTo("www.contoso.com"));
                Assert.That(key.ToDnsEndPoint().Host, Is.EqualTo("www.contoso.com"));
            });
        }

        [Test]
        public void ScopedCcsKeySupportsWildcardHostname()
        {
            var key = new ScopedCcsKey("*.example.com", 443);

            Assert.Multiple(() =>
            {
                Assert.That(key.Hostname, Is.EqualTo("*.example.com"));
                Assert.That(key.ToString(), Is.EqualTo("*.example.com:443"));
            });
        }

        [Test]
        public void ScopedCcsKeyConstructorRejectsHostnameWhitespaceFormatting()
        {
            var endPoint = new DnsEndPoint(" www.contoso.com ", 443);

            ArgumentException ex = Assert.Throws<ArgumentException>(() => new ScopedCcsKey(endPoint));
            Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
        }

        [Test]
        public void ScopedCcsKeyParseRejectsInvalidValue()
        {
            Assert.Multiple(() =>
            {
                Assert.That(ScopedCcsKey.TryParse("127.0.0.1:443", out ScopedCcsKey? key), Is.False);
                Assert.That(key, Is.Null);
                Assert.That(() => ScopedCcsKey.Parse("127.0.0.1:443"), Throws.TypeOf<FormatException>());
            });
        }

        [Test]
        public void ScopedCcsKeyParseRejectsNullValue()
        {
            string? value = null;

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => ScopedCcsKey.Parse(value!));
            Assert.That(ex.ParamName, Is.EqualTo("value"));
        }

        [Test]
        public void ScopedCcsKeyParseReturnsParsedKey()
        {
            ScopedCcsKey key = ScopedCcsKey.Parse("www.contoso.com:443");

            Assert.Multiple(() =>
            {
                Assert.That(key.Hostname, Is.EqualTo("www.contoso.com"));
                Assert.That(key.Port, Is.EqualTo(443));
                Assert.That(key.ToString(), Is.EqualTo("www.contoso.com:443"));
            });
        }

        [Test]
        public void ScopedCcsKeyTryParseReturnsFalseForMalformedValue()
        {
            bool result = ScopedCcsKey.TryParse("localhost", out ScopedCcsKey? key);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.False);
                Assert.That(key, Is.Null);
            });
        }

        [Test]
        public void ScopedCcsKeyConstructorRejectsNullDnsEndPoint()
        {
            DnsEndPoint? endPoint = null;

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => new ScopedCcsKey(endPoint!));
            Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
        }

        [Test]
        public void ScopedCcsKeyConstructorRejectsNullHostname()
        {
            string? hostname = null;

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => new ScopedCcsKey(hostname!, 443));
            Assert.That(ex.ParamName, Is.EqualTo("hostname"));
        }

        [Test]
        public void ScopedCcsKeyObjectEqualityRejectsUnsupportedType()
        {
            var key = new ScopedCcsKey("www.contoso.com", 443);

            Assert.That(key.Equals("www.contoso.com:443"), Is.False);
        }

        [Test]
        public void ScopedCcsKeyTypedEqualityRejectsNullValues()
        {
            var key = new ScopedCcsKey("www.contoso.com", 443);
            ScopedCcsKey? otherKey = null;
            DnsEndPoint? endPoint = null;

            Assert.Multiple(() =>
            {
                Assert.That(key.Equals(otherKey), Is.False);
                Assert.That(key.Equals(endPoint), Is.False);
            });
        }

        [Test]
        public void ScopedCcsKeyNullImplicitConversionReturnsNullEndPoint()
        {
            ScopedCcsKey? key = null;
            DnsEndPoint? endPoint = key;

            Assert.That(endPoint, Is.Null);
        }

        [Test]
        public void IpPortKeyConstructorRejectsNullIpEndPoint()
        {
            IPEndPoint? endPoint = null;

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => new IpPortKey(endPoint!));
            Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
        }

        [Test]
        public void IpPortKeyConstructorRejectsNullAddress()
        {
            IPAddress? address = null;

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => new IpPortKey(address!, 443));
            Assert.That(ex.ParamName, Is.EqualTo("address"));
        }

        [Test]
        public void HostnamePortKeyConstructorRejectsWhitespaceHost()
        {
            var endPoint = new DnsEndPoint("   ", 443);

            ArgumentException ex = Assert.Throws<ArgumentException>(() => new HostnamePortKey(endPoint));
            Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
        }

        [Test]
        public void ScopedCcsKeyConstructorRejectsWhitespaceHost()
        {
            var endPoint = new DnsEndPoint("   ", 443);

            ArgumentException ex = Assert.Throws<ArgumentException>(() => new ScopedCcsKey(endPoint));
            Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
        }

        [Test]
        public void ScopedCcsKeyConstructorRejectsIpAddressHost()
        {
            ArgumentException ex = Assert.Throws<ArgumentException>(() => new ScopedCcsKey("127.0.0.1", 443));
            Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
        }
    }
}
