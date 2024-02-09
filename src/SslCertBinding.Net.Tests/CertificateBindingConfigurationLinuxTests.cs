using NUnit.Framework;
using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
#endif
    public class CertificateBindingConfigurationLinuxTests
    {        
        [Test]
        public void AnyUseOfCertificateBindingConfigurationOnLinuxIsNotSupported()
        {
#pragma warning disable CA1416 // Validate platform compatibility
            var config = new CertificateBindingConfiguration();

            TestDelegate[] ops = {
                () => _ = config.Query(),
                () => config.Delete(new IPEndPoint(1, 1)),
                () => config.Bind(new CertificateBinding("asdasd", StoreName.My, new IPEndPoint(1,1), Guid.Empty)),
            };
            
            foreach (var op in ops) {
                var ex = Assert.Throws<PlatformNotSupportedException>(op);
                Assert.That(ex, Has.InnerException.TypeOf<DllNotFoundException>());
            }
#pragma warning restore CA1416 // Validate platform compatibility
        }
    }
}
