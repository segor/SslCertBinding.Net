using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net.Tests
{
#if NET5_0_OR_GREATER
    [TestFixture]
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public class CertificateBindingConfigurationLinuxTests
    {        
        [Test]
        public void AnyUseOfCertificateBindingConfigurationOnLinuxIsNotSupported()
        {
#pragma warning disable CA1416 // Validate platform compatibility
            var config = new CertificateBindingConfiguration();

            var ops = new Dictionary<string, TestDelegate> {
                {"Query", () => _ = config.Query() },
                {"Delete", () => config.Delete(new IPEndPoint(1, 1)) },
                {"Bind", () => config.Bind(new CertificateBinding("asdasd", StoreName.My, new IPEndPoint(1,1), Guid.Empty)) },
            };
            
            foreach (var (opName, opCode) in ops) {
                var errMessage = $"Operation '{opName}'"; 
                var ex = Assert.Throws<PlatformNotSupportedException>(opCode, errMessage);
                Assert.That(ex, Has.InnerException.TypeOf<DllNotFoundException>(), errMessage);
            }
#pragma warning restore CA1416 // Validate platform compatibility
        }
    }
#endif
}
