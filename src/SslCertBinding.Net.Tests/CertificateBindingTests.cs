using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;

namespace SslCertBinding.Net.Tests
{
    [TestClass()]
    public class CertificateBindingTests
    {
        [TestMethod()]
        public void ConstructorWithEmptyCertificateThumbprintShouldFailTest()
        {
            void constructor()
            {
                new CertificateBinding(String.Empty, "MY", new IPEndPoint(0, 0), Guid.Empty);
            }
            Assert.ThrowsException<ArgumentException>(constructor, "'certificateThumbprint' cannot be null or empty.", "certificateThumbprint" );
        }

        [TestMethod()]
        public void ConstructorWithNullIpportShouldFailTest()
        {
            void constructor()
            {
                new CertificateBinding("certificateThumbprint", "MY", null, Guid.Empty);
            }
            Assert.ThrowsException<ArgumentNullException>(constructor, "'ipPort' cannot be null.", "ipPort");
        }
    }
}