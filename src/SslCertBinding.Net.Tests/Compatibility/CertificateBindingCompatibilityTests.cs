#pragma warning disable CA1416
#pragma warning disable CS0618
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;

#nullable disable
namespace SslCertBinding.Net.Tests
{
    [TestFixture]
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public class CertificateBindingCompatibilityTests
    {
        [Test]
        public void QueryMapsIpBindingsToLegacyShape()
        {
            var ipBinding = new IpPortBinding(
                new IpPortKey(IPAddress.Parse("127.0.0.1"), 443),
                new SslCertificateReference("ABCDEF", StoreName.My),
                Guid.NewGuid(),
                new BindingOptions { DisableTls12 = true });
            var configuration = new CertificateBindingConfiguration(new StubConfiguration
            {
                QueryAllIpBindingsResult = new[] { ipBinding },
            });

            IReadOnlyList<CertificateBinding> result = configuration.Query();

            Assert.Multiple(() =>
            {
                Assert.That(result, Has.Count.EqualTo(1));
                Assert.That(result[0].IpPort, Is.EqualTo(ipBinding.Key.ToIPEndPoint()));
                Assert.That(result[0].Thumbprint, Is.EqualTo(ipBinding.Certificate.Thumbprint));
                Assert.That(result[0].StoreName, Is.EqualTo(ipBinding.Certificate.StoreName));
                Assert.That(result[0].Options.DisableTls12, Is.True);
            });
        }

        [Test]
        public void QueryUsesIpFamilyEnumerationAndNeverMixedBindingEnumeration()
        {
            var stub = new StubConfiguration();
            var ipBinding = new IpPortBinding(
                new IpPortKey(IPAddress.Parse("127.0.0.1"), 443),
                new SslCertificateReference("ABCDEF", StoreName.My),
                Guid.NewGuid());
            var hostnameBinding = new HostnamePortBinding(
                new HostnamePortKey("www.contoso.com", 443),
                new SslCertificateReference("FEDCBA", StoreName.My),
                Guid.NewGuid());
            var ccsBinding = new CcsPortBinding(new CcsPortKey(443), Guid.NewGuid());
            var scopedCcsBinding = new ScopedCcsBinding(new ScopedCcsKey("www.contoso.com", 443), Guid.NewGuid());
            stub.QueryAllIpBindingsResult = new[] { ipBinding };
            stub.QueryAllBindingsResult = new ISslBinding[] { ipBinding, hostnameBinding, ccsBinding, scopedCcsBinding };
            var configuration = new CertificateBindingConfiguration(stub);

            IReadOnlyList<CertificateBinding> result = configuration.Query();

            Assert.Multiple(() =>
            {
                Assert.That(result, Has.Count.EqualTo(1));
                Assert.That(result[0].IpPort, Is.EqualTo(ipBinding.Key.ToIPEndPoint()));
                Assert.That(stub.QueryAllCalled, Is.False);
            });
        }

        [Test]
        public void BindMapsLegacyBindingToNewIpBinding()
        {
            var stub = new StubConfiguration();
            var configuration = new CertificateBindingConfiguration(stub);
            var legacyBinding = new CertificateBinding(
                "ABCDEF",
                StoreName.My,
                new IPEndPoint(IPAddress.Any, 443),
                Guid.NewGuid(),
                new BindingOptions { UseDsMappers = true });

            configuration.Bind(legacyBinding);

            Assert.Multiple(() =>
            {
                Assert.That(stub.UpsertArgument, Is.TypeOf<IpPortBinding>());
                Assert.That(((IpPortBinding)stub.UpsertArgument).Key.ToIPEndPoint(), Is.EqualTo(legacyBinding.IpPort));
                Assert.That(((IpPortBinding)stub.UpsertArgument).Certificate.Thumbprint, Is.EqualTo(legacyBinding.Thumbprint));
                Assert.That(((IpPortBinding)stub.UpsertArgument).Options.UseDsMappers, Is.True);
            });
        }

        [Test]
        public void DeleteMapsLegacyCollectionToIpKeys()
        {
            var stub = new StubConfiguration();
            var configuration = new CertificateBindingConfiguration(stub);
            var endpoints = new[]
            {
                new IPEndPoint(IPAddress.Any, 443),
                new IPEndPoint(IPAddress.Loopback, 444),
            };

            configuration.Delete(endpoints);

            Assert.Multiple(() =>
            {
                Assert.That(stub.DeleteArguments, Has.Count.EqualTo(2));
                Assert.That(stub.DeleteArguments.ElementAt(0), Is.TypeOf<IpPortKey>());
                Assert.That(((IpPortKey)stub.DeleteArguments.ElementAt(0)).ToIPEndPoint(), Is.EqualTo(endpoints[0]));
                Assert.That(((IpPortKey)stub.DeleteArguments.ElementAt(1)).ToIPEndPoint(), Is.EqualTo(endpoints[1]));
            });
        }

        [Test]
        public void FindByIpEndPointUsesTypedFind()
        {
            var endPoint = new IPEndPoint(IPAddress.Loopback, 443);
            var binding = new IpPortBinding(
                new IpPortKey(endPoint),
                new SslCertificateReference("ABCDEF", StoreName.My),
                Guid.NewGuid(),
                new BindingOptions { NegotiateCertificate = true });
            var stub = new StubConfiguration
            {
                FindByIpKeyResult = binding,
            };
            var configuration = new CertificateBindingConfiguration(stub);

            IReadOnlyList<CertificateBinding> result = configuration.Query(endPoint);

            Assert.Multiple(() =>
            {
                Assert.That(stub.FindByIpKeyArgument, Is.EqualTo(binding.Key));
                Assert.That(result, Has.Count.EqualTo(1));
                Assert.That(result[0].IpPort, Is.EqualTo(endPoint));
                Assert.That(result[0].Options.NegotiateCertificate, Is.True);
            });
        }

        [Test]
        public void FindByIpEndPointReturnsEmptyWhenFindMisses()
        {
            var endPoint = new IPEndPoint(IPAddress.Loopback, 443);
            var stub = new StubConfiguration();
            var configuration = new CertificateBindingConfiguration(stub);

            IReadOnlyList<CertificateBinding> result = configuration.Query(endPoint);

            Assert.Multiple(() =>
            {
                Assert.That(stub.FindByIpKeyArgument, Is.EqualTo(new IpPortKey(endPoint)));
                Assert.That(result, Is.Empty);
            });
        }

        [Test]
        public void CertificateBindingConfigurationInternalCtorRejectsNullConfiguration()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => new CertificateBindingConfiguration(null));
            Assert.That(ex.ParamName, Is.EqualTo("configuration"));
        }

        [Test]
        public void CertificateBindingConfigurationPublicCtorCreatesInstance()
        {
            var configuration = new CertificateBindingConfiguration();

            Assert.That(configuration, Is.Not.Null);
        }

        [Test]
        public void BindRejectsNullBinding()
        {
            var configuration = new CertificateBindingConfiguration(new StubConfiguration());

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Bind(null));
            Assert.That(ex.ParamName, Is.EqualTo("binding"));
        }

        [Test]
        public void DeleteRejectsNullEndPoint()
        {
            var configuration = new CertificateBindingConfiguration(new StubConfiguration());

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Delete((IPEndPoint)null));
            Assert.That(ex.ParamName, Is.EqualTo("endPoint"));
        }

        [Test]
        public void DeleteSingleMapsLegacyEndpointToIpKey()
        {
            var endPoint = new IPEndPoint(IPAddress.Any, 443);
            var stub = new StubConfiguration();
            var configuration = new CertificateBindingConfiguration(stub);

            configuration.Delete(endPoint);

            Assert.Multiple(() =>
            {
                Assert.That(stub.DeleteArguments, Has.Count.EqualTo(1));
                Assert.That(stub.DeleteArguments.Single(), Is.TypeOf<IpPortKey>());
                Assert.That(((IpPortKey)stub.DeleteArguments.Single()).ToIPEndPoint(), Is.EqualTo(endPoint));
            });
        }

        [Test]
        public void DeleteRejectsNullCollection()
        {
            var configuration = new CertificateBindingConfiguration(new StubConfiguration());

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Delete((IReadOnlyCollection<IPEndPoint>)null));
            Assert.That(ex.ParamName, Is.EqualTo("endPoints"));
        }

        [Test]
        public void DeleteAcceptsEmptyCollection()
        {
            var stub = new StubConfiguration();
            var configuration = new CertificateBindingConfiguration(stub);

            configuration.Delete(Array.Empty<IPEndPoint>());

            Assert.That(stub.DeleteArguments, Is.Null);
        }

        [Test]
        public void DeleteRejectsCollectionContainingNullItem()
        {
            var configuration = new CertificateBindingConfiguration(new StubConfiguration());
            IPEndPoint[] endPoints = { new IPEndPoint(IPAddress.Any, 443), null };

            ArgumentException ex = Assert.Throws<ArgumentException>(() => configuration.Delete(endPoints));

            Assert.Multiple(() =>
            {
                Assert.That(ex.ParamName, Is.EqualTo("endPoints"));
                Assert.That(ex.Message, Does.Contain("cannot contain null items"));
            });
        }

        [Test]
        public void CertificateBindingRejectsEmptyThumbprint()
        {
            ArgumentException ex = Assert.Throws<ArgumentException>(() =>
                new CertificateBinding(string.Empty, "MY", new IPEndPoint(IPAddress.Any, 443), Guid.Empty));

            Assert.That(ex.ParamName, Is.EqualTo("certificateThumbprint"));
        }

        [Test]
        public void CertificateBindingDefaultsStoreNameToMyWhenNull()
        {
            var binding = new CertificateBinding("ABCDEF", (string)null, new IPEndPoint(IPAddress.Any, 443), Guid.Empty);

            Assert.That(binding.StoreName, Is.EqualTo("MY"));
        }

        [Test]
        public void CertificateBindingFromRejectsNullBinding()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => CertificateBinding.From(null));
            Assert.That(ex.ParamName, Is.EqualTo("binding"));
        }

        [Test]
        public void CertificateBindingToIpPortBindingClonesOptions()
        {
            var options = new BindingOptions
            {
                DisableTls12 = true,
                EnableRevocationFreshnessTime = true,
                NegotiateCertificate = true,
                UseDsMappers = true,
                RevocationFreshnessTime = TimeSpan.FromMinutes(5),
                RevocationUrlRetrievalTimeout = TimeSpan.FromSeconds(30),
                SslCtlIdentifier = "ctl-id",
                SslCtlStoreName = "WebHosting",
            };
            var binding = new CertificateBinding("ABCDEF", "MY", new IPEndPoint(IPAddress.Loopback, 443), Guid.NewGuid(), options);

            IpPortBinding result = binding.ToIpPortBinding();

            Assert.Multiple(() =>
            {
                Assert.That(result.Key.ToIPEndPoint(), Is.EqualTo(binding.IpPort));
                Assert.That(result.Certificate.Thumbprint, Is.EqualTo(binding.Thumbprint));
                Assert.That(result.Certificate.StoreName, Is.EqualTo(binding.StoreName));
                Assert.That(result.Options, Is.Not.SameAs(binding.Options));
                Assert.That(result.Options.DisableTls12, Is.True);
                Assert.That(result.Options.EnableRevocationFreshnessTime, Is.True);
                Assert.That(result.Options.NegotiateCertificate, Is.True);
                Assert.That(result.Options.UseDsMappers, Is.True);
                Assert.That(result.Options.RevocationFreshnessTime, Is.EqualTo(TimeSpan.FromMinutes(5)));
                Assert.That(result.Options.RevocationUrlRetrievalTimeout, Is.EqualTo(TimeSpan.FromSeconds(30)));
                Assert.That(result.Options.SslCtlIdentifier, Is.EqualTo("ctl-id"));
                Assert.That(result.Options.SslCtlStoreName, Is.EqualTo("WebHosting"));
            });
        }

        [Test]
        public void CertificateBindingCloneOptionsReturnsDefaultsForNull()
        {
            BindingOptions clone = CertificateBinding.CloneOptions(null);

            Assert.Multiple(() =>
            {
                Assert.That(clone, Is.Not.Null);
                Assert.That(clone.DisableTls12, Is.False);
                Assert.That(clone.NegotiateCertificate, Is.False);
                Assert.That(clone.SslCtlIdentifier, Is.Null);
            });
        }

        private sealed class StubConfiguration : ISslBindingConfiguration
        {
            public IReadOnlyList<ISslBinding> QueryAllBindingsResult { get; set; } = Array.Empty<ISslBinding>();
            public IReadOnlyList<IpPortBinding> QueryAllIpBindingsResult { get; set; } = Array.Empty<IpPortBinding>();
            public IpPortBinding FindByIpKeyResult { get; set; }
            public ISslBinding UpsertArgument { get; private set; }
            public IReadOnlyCollection<SslBindingKey> DeleteArguments { get; private set; }
            public IpPortKey FindByIpKeyArgument { get; private set; }
            public bool QueryAllCalled { get; private set; }

            public IReadOnlyList<ISslBinding> Query()
            {
                QueryAllCalled = true;
                return QueryAllBindingsResult;
            }

            public IReadOnlyList<TBinding> Query<TBinding>() where TBinding : ISslBinding
            {
                if (typeof(TBinding) == typeof(IpPortBinding))
                {
                    return (IReadOnlyList<TBinding>)(object)QueryAllIpBindingsResult;
                }

                throw new NotSupportedException();
            }

            public IpPortBinding Find(IpPortKey key)
            {
                FindByIpKeyArgument = key;
                return FindByIpKeyResult;
            }

            public HostnamePortBinding Find(HostnamePortKey key)
            {
                throw new NotSupportedException();
            }

            public CcsPortBinding Find(CcsPortKey key)
            {
                throw new NotSupportedException();
            }

            public ScopedCcsBinding Find(ScopedCcsKey key)
            {
                throw new NotSupportedException();
            }

            public ISslBinding Find(SslBindingKey key)
            {
                throw new NotSupportedException();
            }

            public void Upsert(ISslBinding binding)
            {
                UpsertArgument = binding;
            }

            public void Delete(SslBindingKey key)
            {
                DeleteArguments = new[] { key };
            }

            public void Delete(IReadOnlyCollection<SslBindingKey> keys)
            {
                DeleteArguments = keys;
            }
        }
    }
}
#pragma warning restore CS0618
#pragma warning restore CA1416
