using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public class SslBindingConfigurationUpsertIntegrationTests : SslBindingConfigurationIntegrationTestBase
    {
        [Test]
        public async Task UpsertHostnameBinding()
        {
            HostnamePortKey key = await GetFreeHostnameBindingKey();
            var appId = CreateTestAppId();
            var configuration = new SslBindingConfiguration();
            TrackBindingKey(key);

            configuration.Upsert(new HostnamePortBinding(
                key,
                new SslCertificateReference(TestingCertThumbprint, StoreName.My),
                appId,
                new BindingOptions
                {
                    DoNotVerifyCertificateRevocation = true,
                    EnableRevocationFreshnessTime = true,
                    RevocationFreshnessTime = TimeSpan.FromMinutes(1),
                    NegotiateCertificate = true,
                }));

            CertConfigCmd.CommandResult result = await CertConfigCmd.Show((SslBindingKey)key);
            Assert.That(result.IsSuccessfull, Is.True);
            string expectedOutput = string.Format(
                CultureInfo.InvariantCulture,
                @"  name:port                 : {0}
    Certificate Hash        : {1}
    Application ID          : {2}
    Certificate Store Name  : My",
                key,
                TestingCertThumbprint,
                appId.ToString("B"));

            AssertOutput(result.Output, expectedOutput);
        }

        [Test]
        public async Task UpsertIpBinding()
        {
            IpPortKey key = await GetFreeIpPortKey("::");
            var appId = CreateTestAppId();
            var configuration = new SslBindingConfiguration();
            TrackBindingKey(key);

            configuration.Upsert(new IpPortBinding(
                key,
                new SslCertificateReference(TestingCertThumbprint, StoreName.My),
                appId,
                new BindingOptions
                {
                    DoNotPassRequestsToRawFilters = true,
                    DoNotVerifyCertificateRevocation = true,
                    EnableRevocationFreshnessTime = true,
                    NegotiateCertificate = true,
                    NoUsageCheck = true,
                    RevocationFreshnessTime = TimeSpan.FromMinutes(1),
                    RevocationUrlRetrievalTimeout = TimeSpan.FromSeconds(5),
                    UseDsMappers = true,
                    VerifyRevocationWithCachedCertificateOnly = true,
                    DisableTls12 = true,
                }));

            CertConfigCmd.CommandResult result = await CertConfigCmd.Show((SslBindingKey)key);
            Assert.That(result.IsSuccessfull, Is.True);
            Assert.Multiple(() =>
            {
                AssertOutput(result.Output, string.Format(CultureInfo.InvariantCulture, @"IP:port : {0}", key));
                AssertOutput(result.Output, string.Format(CultureInfo.InvariantCulture, @"Certificate Hash : {0}", TestingCertThumbprint));
                AssertOutput(result.Output, string.Format(CultureInfo.InvariantCulture, @"Application ID : {0}", appId.ToString("B")));
                AssertOutput(result.Output, @"Certificate Store Name : My");
                AssertOutput(result.Output, @"Verify Client Certificate Revocation : Disabled");
                AssertOutput(result.Output, @"Verify Revocation Using Cached Client Certificate Only : Enabled");
                AssertOutput(result.Output, @"Use Revocation Freshness Time : Enabled");
                AssertOutput(result.Output, @"Usage Check : Disabled");
                AssertOutput(result.Output, @"Revocation Freshness Time : 60");
                AssertOutput(result.Output, @"URL Retrieval Timeout : 5000");
                AssertOutput(result.Output, @"DS Mapper Usage : Enabled");
                AssertOutput(result.Output, @"Negotiate Client Certificate : Enabled");
                AssertOutput(result.Output, @"Disable TLS1.2 : Set");
            });
        }

        [Test]
        public async Task UpsertCcsBinding()
        {
            CcsPortKey key = await GetFreeCcsPortKey();
            var appId = CreateTestAppId();
            var configuration = new SslBindingConfiguration();
            TrackBindingKey(key);

            configuration.Upsert(new CcsPortBinding(key, appId));

            CcsPortBinding binding = configuration.Query(key).Single();
            AssertBindingMatches(binding, key, appId, new BindingOptions(), null);
        }

        [Test]
        public async Task UpsertScopedCcsBinding()
        {
            ScopedCcsKey key = await GetFreeScopedCcsKey("ssl-cert-binding.net.com");
            var appId = CreateTestAppId();
            var configuration = new SslBindingConfiguration();
            TrackBindingKey(key);

            configuration.Upsert(new ScopedCcsBinding(key, appId, new BindingOptions
            {
                UseDsMappers = true,
                DisableTls12 = true,
            }));

            ScopedCcsBinding binding = configuration.Query(key).Single();
            AssertBindingMatches(binding, key, appId, new BindingOptions
            {
                UseDsMappers = true,
                DisableTls12 = true,
            }, null);
        }

        [Test]
        public Task BindingOptionsRoundTripIpPortDefaults()
        {
            return AssertBindingOptionsRoundTrip(SslBindingKind.IpPort, CreateDefaultBindingOptions());
        }

        [Test]
        public Task BindingOptionsRoundTripHostnamePortDefaults()
        {
            return AssertBindingOptionsRoundTrip(SslBindingKind.HostnamePort, CreateDefaultBindingOptions());
        }

        [Test]
        public Task BindingOptionsRoundTripIpPortAllEnabled()
        {
            return AssertBindingOptionsRoundTrip(SslBindingKind.IpPort, CreateAllEnabledBindingOptions());
        }

        [Test]
        public Task BindingOptionsRoundTripHostnamePortAllEnabled()
        {
            return AssertBindingOptionsRoundTrip(SslBindingKind.HostnamePort, CreateAllEnabledBindingOptions());
        }

        [Test]
        public Task BindingOptionsRoundTripIpPortMixed()
        {
            return AssertBindingOptionsRoundTrip(SslBindingKind.IpPort, CreateMixedBindingOptions());
        }

        [Test]
        public Task BindingOptionsRoundTripHostnamePortMixed()
        {
            return AssertBindingOptionsRoundTrip(SslBindingKind.HostnamePort, CreateMixedBindingOptions());
        }

        [Test]
        public Task BindingOptionsRoundTripCcsPortMixed()
        {
            return AssertBindingOptionsRoundTrip(SslBindingKind.CcsPort, CreateDefaultBindingOptions());
        }

        [Test]
        public Task BindingOptionsRoundTripScopedCcsMixed()
        {
            return AssertBindingOptionsRoundTrip(SslBindingKind.ScopedCcs, CreateMixedBindingOptions());
        }

        [TestCase(SslBindingKind.IpPort, TestName = "UpsertExistingBinding_IpPort")]
        [TestCase(SslBindingKind.HostnamePort, TestName = "UpsertExistingBinding_HostnamePort")]
        [TestCase(SslBindingKind.CcsPort, TestName = "UpsertExistingBinding_CcsPort")]
        [TestCase(SslBindingKind.ScopedCcs, TestName = "UpsertExistingBinding_ScopedCcs")]
        public async Task UpsertExistingBindingReplacesValues(SslBindingKind kind)
        {
            SslBindingKey key = await GetFreeBindingKey(
                kind,
                kind == SslBindingKind.IpPort
                    ? "::"
                    : (kind == SslBindingKind.HostnamePort || kind == SslBindingKind.ScopedCcs ? "ssl-cert-binding.net.com" : null));
            var originalAppId = CreateTestAppId();
            var updatedAppId = CreateTestAppId();
            BindingOptions expectedOptions = kind == SslBindingKind.CcsPort
                ? CreateCcsAllEnabledBindingOptions()
                : CreateAllEnabledBindingOptions();
            TrackBindingKey(key);

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = key,
                certhash = TestingCertThumbprint,
                appid = originalAppId,
                certstorename = kind == SslBindingKind.IpPort || kind == SslBindingKind.HostnamePort ? StoreName.AuthRoot.ToString() : null,
            });

            var configuration = new SslBindingConfiguration();
            configuration.Upsert(CreateBinding(key, updatedAppId, expectedOptions));

            ISslBinding binding = QuerySingleBinding(configuration, key);
            AssertBindingMatches(
                binding,
                key,
                updatedAppId,
                expectedOptions,
                kind == SslBindingKind.IpPort || kind == SslBindingKind.HostnamePort ? StoreName.My.ToString() : null);
        }

        private async Task AssertBindingOptionsRoundTrip(SslBindingKind kind, BindingOptions expectedOptions)
        {
            SslBindingKey key = await GetFreeBindingKey(kind);
            var appId = CreateTestAppId();
            var configuration = new SslBindingConfiguration();
            TrackBindingKey(key);

            configuration.Upsert(CreateBinding(key, appId, expectedOptions));

            ISslBinding binding = QuerySingleBinding(configuration, key);

            Assert.Multiple(() =>
            {
                Assert.That(binding.Key, Is.EqualTo(key));
                Assert.That(binding.AppId, Is.EqualTo(appId));
                bool hasCertificate = TryGetCertificate(binding, out SslCertificateReference certificate);
                if (kind == SslBindingKind.IpPort || kind == SslBindingKind.HostnamePort)
                {
                    Assert.That(hasCertificate, Is.True);
                    Assert.That(certificate.Thumbprint, Is.EqualTo(TestingCertThumbprint));
                    Assert.That(string.Equals(certificate.StoreName, StoreName.My.ToString(), StringComparison.OrdinalIgnoreCase), Is.True);
                }
                else
                {
                    Assert.That(hasCertificate, Is.False);
                }

                AssertBindingOptions(binding.Options, expectedOptions);
            });
        }
    }
}
