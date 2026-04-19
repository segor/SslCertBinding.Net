using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public class SslBindingConfigurationQueryIntegrationTests : SslBindingConfigurationIntegrationTestBase
    {
        [TestCase(SslBindingKind.IpPort, "0.0.0.0", TestName = "QueryExistingBinding_IpPort_Ipv4Any")]
        [TestCase(SslBindingKind.IpPort, "::", TestName = "QueryExistingBinding_IpPort_Ipv6Any")]
        [TestCase(SslBindingKind.HostnamePort, "localhost", TestName = "QueryExistingBinding_HostnamePort_Localhost")]
        [TestCase(SslBindingKind.HostnamePort, "ssl-cert-binding.net.com", TestName = "QueryExistingBinding_HostnamePort_CustomHostname")]
        [TestCase(SslBindingKind.CcsPort, null, TestName = "QueryExistingBinding_CcsPort")]
        [TestCase(SslBindingKind.ScopedCcs, "localhost", TestName = "QueryExistingBinding_ScopedCcs_Localhost")]
        [TestCase(SslBindingKind.ScopedCcs, "ssl-cert-binding.net.com", TestName = "QueryExistingBinding_ScopedCcs_CustomHostname")]
        public async Task QueryExistingBinding(SslBindingKind kind, string value)
        {
            SslBindingKey key = await GetFreeBindingKey(kind, value);
            var appId = CreateTestAppId();
            TrackBindingKey(key);
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = key,
                certhash = TestingCertThumbprint,
                appid = appId,
                certstorename = null,
            });

            var configuration = new SslBindingConfiguration();
            ISslBinding binding = QuerySingleBinding(configuration, key);

            AssertBindingMatches(
                binding,
                key,
                appId,
                CreateDefaultBindingOptions(),
                kind == SslBindingKind.IpPort || kind == SslBindingKind.HostnamePort ? StoreName.My.ToString() : null);
        }

        [TestCase(SslBindingKind.IpPort, "0.0.0.0", TestName = "QueryMissingBinding_IpPort_Ipv4Any")]
        [TestCase(SslBindingKind.IpPort, "::", TestName = "QueryMissingBinding_IpPort_Ipv6Any")]
        [TestCase(SslBindingKind.HostnamePort, "localhost", TestName = "QueryMissingBinding_HostnamePort_Localhost")]
        [TestCase(SslBindingKind.HostnamePort, "ssl-cert-binding.net.com", TestName = "QueryMissingBinding_HostnamePort_CustomHostname")]
        [TestCase(SslBindingKind.CcsPort, null, TestName = "QueryMissingBinding_CcsPort")]
        [TestCase(SslBindingKind.ScopedCcs, "localhost", TestName = "QueryMissingBinding_ScopedCcs_Localhost")]
        [TestCase(SslBindingKind.ScopedCcs, "ssl-cert-binding.net.com", TestName = "QueryMissingBinding_ScopedCcs_CustomHostname")]
        public async Task QueryMissingBindingReturnsEmpty(SslBindingKind kind, string value)
        {
            SslBindingKey key = await GetFreeBindingKey(kind, value);
            var configuration = new SslBindingConfiguration();

            switch (key)
            {
                case IpPortKey ipKey:
                    Assert.That(configuration.Query(ipKey), Is.Empty);
                    break;
                case HostnamePortKey hostnameKey:
                    Assert.That(configuration.Query(hostnameKey), Is.Empty);
                    break;
                case CcsPortKey ccsKey:
                    Assert.That(configuration.Query(ccsKey), Is.Empty);
                    break;
                case ScopedCcsKey scopedCcsKey:
                    Assert.That(configuration.Query(scopedCcsKey), Is.Empty);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        [Test]
        public async Task QueryAllReturnsAllBindingFamilies()
        {
            IpPortKey ipKey = await GetFreeIpPortKey();
            HostnamePortKey hostnameKey = await GetFreeHostnameBindingKey();
            CcsPortKey ccsKey = await GetFreeCcsPortKey();
            ScopedCcsKey scopedCcsKey = await GetFreeScopedCcsKey("ssl-cert-binding.net.com");
            TrackBindingKey(ipKey);
            TrackBindingKey(hostnameKey);
            TrackBindingKey(ccsKey);
            TrackBindingKey(scopedCcsKey);

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = ipKey,
                certhash = TestingCertThumbprint,
                appid = CreateTestAppId(),
                certstorename = StoreName.My.ToString(),
            });

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = hostnameKey,
                certhash = TestingCertThumbprint,
                appid = CreateTestAppId(),
                certstorename = StoreName.My.ToString(),
            });

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = ccsKey,
                appid = CreateTestAppId(),
            });

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = scopedCcsKey,
                appid = CreateTestAppId(),
            });

            var configuration = new SslBindingConfiguration();
            IReadOnlyList<ISslBinding> bindings = configuration.Query();

            Assert.Multiple(() =>
            {
                Assert.That(bindings.OfType<IpPortBinding>().Any(binding => binding.Key.Equals(ipKey)), Is.True);
                Assert.That(bindings.OfType<HostnamePortBinding>().Any(binding => binding.Key.Equals(hostnameKey)), Is.True);
                Assert.That(bindings.OfType<CcsPortBinding>().Any(binding => binding.Key.Equals(ccsKey)), Is.True);
                Assert.That(bindings.OfType<ScopedCcsBinding>().Any(binding => binding.Key.Equals(scopedCcsKey)), Is.True);
            });
        }

        [Test]
        public async Task QueryByBindingTypeReturnsMatchingFamily()
        {
            IpPortKey ipKey = await GetFreeIpPortKey();
            HostnamePortKey hostnameKey = await GetFreeHostnameBindingKey();
            CcsPortKey ccsKey = await GetFreeCcsPortKey();
            ScopedCcsKey scopedCcsKey = await GetFreeScopedCcsKey("ssl-cert-binding.net.com");
            TrackBindingKey(ipKey);
            TrackBindingKey(hostnameKey);
            TrackBindingKey(ccsKey);
            TrackBindingKey(scopedCcsKey);

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = ipKey,
                certhash = TestingCertThumbprint,
                appid = CreateTestAppId(),
                certstorename = StoreName.My.ToString(),
            });

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = hostnameKey,
                certhash = TestingCertThumbprint,
                appid = CreateTestAppId(),
                certstorename = StoreName.My.ToString(),
            });

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = ccsKey,
                appid = CreateTestAppId(),
            });

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = scopedCcsKey,
                appid = CreateTestAppId(),
            });

            var configuration = new SslBindingConfiguration();
            IReadOnlyList<IpPortBinding> ipBindings = configuration.Query<IpPortBinding>();
            IReadOnlyList<HostnamePortBinding> hostnameBindings = configuration.Query<HostnamePortBinding>();
            IReadOnlyList<CcsPortBinding> ccsBindings = configuration.Query<CcsPortBinding>();
            IReadOnlyList<ScopedCcsBinding> scopedCcsBindings = configuration.Query<ScopedCcsBinding>();

            Assert.Multiple(() =>
            {
                Assert.That(ipBindings.Any(binding => binding.Key.Equals(ipKey)), Is.True);
                Assert.That(ipBindings.All(binding => binding is IpPortBinding), Is.True);
                Assert.That(hostnameBindings.Any(binding => binding.Key.Equals(hostnameKey)), Is.True);
                Assert.That(hostnameBindings.All(binding => binding is HostnamePortBinding), Is.True);
                Assert.That(ccsBindings.Any(binding => binding.Key.Equals(ccsKey)), Is.True);
                Assert.That(ccsBindings.All(binding => binding is CcsPortBinding), Is.True);
                Assert.That(scopedCcsBindings.Any(binding => binding.Key.Equals(scopedCcsKey)), Is.True);
                Assert.That(scopedCcsBindings.All(binding => binding is ScopedCcsBinding), Is.True);
            });
        }

        [Test]
        public async Task QueryEnumerationsPreserveBindingOptions()
        {
            IpPortKey ipKey = await GetFreeIpPortKey("::");
            HostnamePortKey hostnameKey = await GetFreeHostnameBindingKey("ssl-cert-binding.net.com");
            BindingOptions ipOptions = CreateAllEnabledBindingOptions();
            BindingOptions hostnameOptions = CreateMixedBindingOptions();
            CcsPortKey ccsKey = await GetFreeCcsPortKey();
            ScopedCcsKey scopedCcsKey = await GetFreeScopedCcsKey("ssl-cert-binding.net.com");
            BindingOptions ccsOptions = CreateCcsMixedBindingOptions();
            BindingOptions scopedCcsOptions = CreateAllEnabledBindingOptions();
            var ipAppId = CreateTestAppId();
            var hostnameAppId = CreateTestAppId();
            var ccsAppId = CreateTestAppId();
            var scopedCcsAppId = CreateTestAppId();
            TrackBindingKey(ipKey);
            TrackBindingKey(hostnameKey);
            TrackBindingKey(ccsKey);
            TrackBindingKey(scopedCcsKey);

            var configuration = new SslBindingConfiguration();
            configuration.Upsert(CreateBinding(ipKey, ipAppId, ipOptions));
            configuration.Upsert(CreateBinding(hostnameKey, hostnameAppId, hostnameOptions));
            configuration.Upsert(CreateBinding(ccsKey, ccsAppId, ccsOptions));
            configuration.Upsert(CreateBinding(scopedCcsKey, scopedCcsAppId, scopedCcsOptions));

            IReadOnlyList<ISslBinding> allBindings = configuration.Query();
            IReadOnlyList<IpPortBinding> ipBindings = configuration.Query<IpPortBinding>();
            IReadOnlyList<HostnamePortBinding> hostnameBindings = configuration.Query<HostnamePortBinding>();
            IReadOnlyList<CcsPortBinding> ccsBindings = configuration.Query<CcsPortBinding>();
            IReadOnlyList<ScopedCcsBinding> scopedCcsBindings = configuration.Query<ScopedCcsBinding>();

            AssertBindingMatches(allBindings.Single(binding => binding.Key.Equals(ipKey)), ipKey, ipAppId, ipOptions, StoreName.My.ToString());
            AssertBindingMatches(allBindings.Single(binding => binding.Key.Equals(hostnameKey)), hostnameKey, hostnameAppId, hostnameOptions, StoreName.My.ToString());
            AssertBindingMatches(allBindings.Single(binding => binding.Key.Equals(ccsKey)), ccsKey, ccsAppId, ccsOptions, null);
            AssertBindingMatches(allBindings.Single(binding => binding.Key.Equals(scopedCcsKey)), scopedCcsKey, scopedCcsAppId, scopedCcsOptions, null);
            AssertBindingMatches(ipBindings.Single(binding => binding.Key.Equals(ipKey)), ipKey, ipAppId, ipOptions, StoreName.My.ToString());
            AssertBindingMatches(hostnameBindings.Single(binding => binding.Key.Equals(hostnameKey)), hostnameKey, hostnameAppId, hostnameOptions, StoreName.My.ToString());
            AssertBindingMatches(ccsBindings.Single(binding => binding.Key.Equals(ccsKey)), ccsKey, ccsAppId, ccsOptions, null);
            AssertBindingMatches(scopedCcsBindings.Single(binding => binding.Key.Equals(scopedCcsKey)), scopedCcsKey, scopedCcsAppId, scopedCcsOptions, null);
        }

        [Test]
        public async Task QueryGenericBaseTypeReturnsAllBindings()
        {
            IpPortKey ipKey = await GetFreeIpPortKey();
            HostnamePortKey hostnameKey = await GetFreeHostnameBindingKey();
            CcsPortKey ccsKey = await GetFreeCcsPortKey();
            ScopedCcsKey scopedCcsKey = await GetFreeScopedCcsKey("ssl-cert-binding.net.com");
            TrackBindingKey(ipKey);
            TrackBindingKey(hostnameKey);
            TrackBindingKey(ccsKey);
            TrackBindingKey(scopedCcsKey);

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = ipKey,
                certhash = TestingCertThumbprint,
                appid = CreateTestAppId(),
                certstorename = StoreName.My.ToString(),
            });

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = hostnameKey,
                certhash = TestingCertThumbprint,
                appid = CreateTestAppId(),
                certstorename = StoreName.My.ToString(),
            });

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = ccsKey,
                appid = CreateTestAppId(),
            });

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = scopedCcsKey,
                appid = CreateTestAppId(),
            });

            var configuration = new SslBindingConfiguration();
            IReadOnlyList<ISslBinding> bindings = configuration.Query<ISslBinding>();

            Assert.Multiple(() =>
            {
                Assert.That(bindings.OfType<IpPortBinding>().Any(binding => binding.Key.Equals(ipKey)), Is.True);
                Assert.That(bindings.OfType<HostnamePortBinding>().Any(binding => binding.Key.Equals(hostnameKey)), Is.True);
                Assert.That(bindings.OfType<CcsPortBinding>().Any(binding => binding.Key.Equals(ccsKey)), Is.True);
                Assert.That(bindings.OfType<ScopedCcsBinding>().Any(binding => binding.Key.Equals(scopedCcsKey)), Is.True);
            });
        }
    }
}
