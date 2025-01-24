using System;
using System.Net;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    public class CertificateBindingTests
    {
        [Test]
        public void ConstructorWithEmptyCertificateThumbprintShouldFailTest()
        {
            void constructor() => _ = new CertificateBinding(string.Empty, "MY", new IPEndPoint(0, 0).ToDnsEndPoint(), Guid.Empty);

            ArgumentException ex = Assert.Throws<ArgumentException>(constructor);
            Assert.Multiple(() =>
            {
                Assert.That(ex.Message, Does.StartWith("Value cannot be null or empty."));
                Assert.That(ex.ParamName, Is.EqualTo("certificateThumbprint"));
            });
        }

        [Test]
        public void ConstructorWithNullIpportShouldFailTest()
        {
            void constructor() => _ = new CertificateBinding("certificateThumbprint", "MY", null, Guid.Empty);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(constructor);
            Assert.Multiple(() =>
            {
                Assert.That(ex.Message, Does.StartWith("Value cannot be null."));
                Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
            });
        }
    }
}
