using NUnit.Framework;
using System;
using System.Net;

namespace SslCertBinding.Net.Tests
{
#if NET5_0_OR_GREATER
#pragma warning disable CA1416 // Validate platform compatibility
    [TestFixture]
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public class CertificateBindingConfigurationLinuxTests
    {
        [Test]
        public void QueryOnLinuxIsNotSupported()
        {
            var config = new CertificateBindingConfiguration();
            var ex = Assert.Throws<PlatformNotSupportedException>(() => _ = config.Query());
            Assert.That(ex, Has.InnerException.TypeOf<DllNotFoundException>());
        }

        [Test]
        public void DeleteOnLinuxIsNotSupported()
        {
            var config = new CertificateBindingConfiguration();
            var endPoint = new IPEndPoint(1, 1);
            var ex = Assert.Throws<PlatformNotSupportedException>(() => config.Delete(endPoint));
            Assert.That(ex, Has.InnerException.TypeOf<DllNotFoundException>());
        }

        [Test]
        public void BindOnLinuxIsNotSupported()
        {
            var config = new CertificateBindingConfiguration();
            var binding = new CertificateBinding("98BC1AACBC38F564B95E1499FA2BA0FC30899A3E", "MY", new IPEndPoint(1, 1), Guid.Empty);
            var ex = Assert.Throws<PlatformNotSupportedException>(() => config.Bind(binding));
            Assert.That(ex, Has.InnerException.TypeOf<DllNotFoundException>());
        }
    }
#pragma warning restore CA1416 // Validate platform compatibility
#endif
}
