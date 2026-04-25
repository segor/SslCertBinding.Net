#if NET5_0_OR_GREATER
#pragma warning disable CA1416 // Validate platform compatibility
using System;
using System.Net;
using NUnit.Framework;

#nullable disable
namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public class SslBindingConfigurationLinuxTests
    {
        [Test]
        public void QueryAllOnLinuxIsNotSupported()
        {
            var config = new SslBindingConfiguration();
            PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() => _ = config.Query());
            Assert.That(ex.InnerException, Is.Null);
        }

        [Test]
        public void FindByIpKeyOnLinuxIsNotSupported()
        {
            var config = new SslBindingConfiguration();
            PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() => _ = config.Find(new IpPortKey(IPAddress.Any, 443)));
            Assert.That(ex.InnerException, Is.Null);
        }

        [Test]
        public void FindByIpEndPointOnLinuxIsNotSupported()
        {
            var config = new SslBindingConfiguration();
            PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() => _ = config.Find(new IPEndPoint(IPAddress.Any, 443).ToIpPortKey()));
            Assert.That(ex.InnerException, Is.Null);
        }

        [Test]
        public void FindByDnsEndPointOnLinuxIsNotSupported()
        {
            var config = new SslBindingConfiguration();
            PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() => _ = config.Find(new DnsEndPoint("localhost", 443).ToHostnamePortKey()));
            Assert.That(ex.InnerException, Is.Null);
        }

        [Test]
        public void FindByScopedCcsDnsEndPointOnLinuxIsNotSupported()
        {
            var config = new SslBindingConfiguration();
            PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() => _ = config.Find(new DnsEndPoint("localhost", 443).ToScopedCcsKey()));
            Assert.That(ex.InnerException, Is.Null);
        }

        [Test]
        public void DeleteOnLinuxIsNotSupported()
        {
            var config = new SslBindingConfiguration();
            PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() => config.Delete(new IpPortKey(IPAddress.Any, 443)));
            Assert.That(ex.InnerException, Is.Null);
        }

        [Test]
        public void DeleteByIpEndPointOnLinuxIsNotSupported()
        {
            var config = new SslBindingConfiguration();
            PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() => config.Delete(new IPEndPoint(IPAddress.Any, 443).ToIpPortKey()));
            Assert.That(ex.InnerException, Is.Null);
        }

        [Test]
        public void DeleteByDnsEndPointOnLinuxIsNotSupported()
        {
            var config = new SslBindingConfiguration();
            PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() => config.Delete(new DnsEndPoint("localhost", 443).ToHostnamePortKey()));
            Assert.That(ex.InnerException, Is.Null);
        }

        [Test]
        public void DeleteByScopedCcsDnsEndPointOnLinuxIsNotSupported()
        {
            var config = new SslBindingConfiguration();
            PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() => config.Delete(new DnsEndPoint("localhost", 443).ToScopedCcsKey()));
            Assert.That(ex.InnerException, Is.Null);
        }

        [Test]
        public void UpsertOnLinuxIsNotSupported()
        {
            var config = new SslBindingConfiguration();
            var binding = new HostnamePortBinding(
                new HostnamePortKey("localhost", 443),
                new SslCertificateReference("98BC1AACBC38F564B95E1499FA2BA0FC30899A3E", "MY"),
                Guid.Empty);
            PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() => config.Upsert(binding));
            Assert.That(ex.InnerException, Is.Null);
        }
    }
}
#pragma warning restore CA1416 // Validate platform compatibility
#endif
