using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using SslCertBinding.Net.Internal.Interop;
using SslCertBinding.Net.Tests.Properties;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    public class SslBindingTests
    {
        [Test]
        public void SslCertificateReferenceRejectsEmptyThumbprint()
        {
            void Constructor()
            {
                _ = new SslCertificateReference(string.Empty, "MY");
            }

            ArgumentException ex = Assert.Throws<ArgumentException>(Constructor);
            Assert.That(ex.ParamName, Is.EqualTo("thumbprint"));
        }

        [Test]
        public void SslCertificateReferenceFromCertificateCopiesThumbprintAndStoreName()
        {
            using (var certificate = new X509Certificate2(
                Resources.certCA,
                string.Empty,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet))
            {
                SslCertificateReference reference = SslCertificateReference.From(certificate, StoreName.My);

                Assert.Multiple(() =>
                {
                    Assert.That(reference.Thumbprint, Is.EqualTo(certificate.Thumbprint));
                    Assert.That(reference.StoreName, Is.EqualTo(StoreName.My.ToString()));
                });
            }
        }

        [Test]
        public void SslCertificateReferenceFromCertificateAndStringStoreCopiesThumbprintAndStoreName()
        {
            using (var certificate = new X509Certificate2(
                Resources.certCA,
                string.Empty,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet))
            {
                SslCertificateReference reference = SslCertificateReference.From(certificate, "WebHosting");

                Assert.Multiple(() =>
                {
                    Assert.That(reference.Thumbprint, Is.EqualTo(certificate.Thumbprint));
                    Assert.That(reference.StoreName, Is.EqualTo("WebHosting"));
                });
            }
        }

        [Test]
        public void SslCertificateReferenceDefaultsStoreNameToMyWhenNull()
        {
            var reference = new SslCertificateReference("thumbprint", (string)null);

            Assert.That(reference.StoreName, Is.EqualTo("MY"));
        }

        [Test]
        public void SslCertificateReferenceFromCertificateAndStoreNameRejectsNullCertificate()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => SslCertificateReference.From((X509Certificate2)null, StoreName.My));
            Assert.That(ex.ParamName, Is.EqualTo("certificate"));
        }

        [Test]
        public void SslCertificateReferenceFromCertificateAndStringStoreRejectsNullCertificate()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => SslCertificateReference.From((X509Certificate2)null, "MY"));
            Assert.That(ex.ParamName, Is.EqualTo("certificate"));
        }

        [Test]
        public void SafeInteropResultDisposeIsIdempotent()
        {
            int disposeCalls = 0;
            var result = new SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY>(
                new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(IntPtr.Zero),
                () => disposeCalls++);

            result.Dispose();
            result.Dispose();

            Assert.That(disposeCalls, Is.EqualTo(1));
        }

        [Test]
        public void SafeInteropResultDisposeWithNullDisposeActionsDoesNotThrow()
        {
            var result = new SafeInteropResult<HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY>(
                new HttpApi.HTTP_SERVICE_CONFIG_SSL_KEY(IntPtr.Zero),
                null);

            Assert.That(() => result.Dispose(), Throws.Nothing);
        }

        [Test]
        public void IpPortBindingRejectsNullKey()
        {
            void Constructor()
            {
                _ = new IpPortBinding(null, new SslCertificateReference("thumbprint", "MY"), Guid.Empty);
            }

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(Constructor);
            Assert.That(ex.ParamName, Is.EqualTo("key"));
        }

        [Test]
        public void HostnamePortBindingExposesKey()
        {
            var key = new HostnamePortKey("localhost", 443);
            var binding = new HostnamePortBinding(key, new SslCertificateReference("thumbprint", "MY"), Guid.Empty);

            Assert.Multiple(() =>
            {
                Assert.That(binding.Kind, Is.EqualTo(SslBindingKind.HostnamePort));
                Assert.That(binding.Key, Is.EqualTo(key));
            });
        }

        [Test]
        public void HostnamePortBindingStringConstructorCreatesCertificateReference()
        {
            var key = new HostnamePortKey("localhost", 443);
            var binding = new HostnamePortBinding(key, "thumbprint", "WebHosting", Guid.Empty);

            Assert.Multiple(() =>
            {
                Assert.That(binding.Key, Is.EqualTo(key));
                Assert.That(binding.Certificate.Thumbprint, Is.EqualTo("thumbprint"));
                Assert.That(binding.Certificate.StoreName, Is.EqualTo("WebHosting"));
            });
        }

        [Test]
        public void IpPortBindingExposesKey()
        {
            var key = new IpPortKey(IPAddress.Any, 443);
            var binding = new IpPortBinding(key, new SslCertificateReference("thumbprint", "MY"), Guid.Empty);

            Assert.Multiple(() =>
            {
                Assert.That(binding.Kind, Is.EqualTo(SslBindingKind.IpPort));
                Assert.That(binding.Key, Is.EqualTo(key));
            });
        }

        [Test]
        public void IpPortBindingStringConstructorCreatesCertificateReference()
        {
            var key = new IpPortKey(IPAddress.Any, 443);
            var binding = new IpPortBinding(key, "thumbprint", "WebHosting", Guid.Empty);

            Assert.Multiple(() =>
            {
                Assert.That(binding.Key, Is.EqualTo(key));
                Assert.That(binding.Certificate.Thumbprint, Is.EqualTo("thumbprint"));
                Assert.That(binding.Certificate.StoreName, Is.EqualTo("WebHosting"));
            });
        }

        [Test]
        public void CcsPortBindingExposesKey()
        {
            var key = new CcsPortKey(443);
            var binding = new CcsPortBinding(key, Guid.Empty);

            Assert.Multiple(() =>
            {
                Assert.That(binding.Kind, Is.EqualTo(SslBindingKind.CcsPort));
                Assert.That(binding.Key, Is.EqualTo(key));
            });
        }

        [Test]
        public void CcsPortBindingRejectsNullKey()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => new CcsPortBinding(null, Guid.Empty));
            Assert.That(ex.ParamName, Is.EqualTo("key"));
        }

        [Test]
        public void ScopedCcsBindingExposesKey()
        {
            var key = new ScopedCcsKey("localhost", 443);
            var binding = new ScopedCcsBinding(key, Guid.Empty);

            Assert.Multiple(() =>
            {
                Assert.That(binding.Kind, Is.EqualTo(SslBindingKind.ScopedCcs));
                Assert.That(binding.Key, Is.EqualTo(key));
            });
        }

        [Test]
        public void ScopedCcsBindingRejectsNullKey()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => new ScopedCcsBinding(null, Guid.Empty));
            Assert.That(ex.ParamName, Is.EqualTo("key"));
        }
    }
}
