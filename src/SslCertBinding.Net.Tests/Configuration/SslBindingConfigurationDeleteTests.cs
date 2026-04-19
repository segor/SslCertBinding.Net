using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public class SslBindingConfigurationDeleteIntegrationTests : SslBindingConfigurationIntegrationTestBase
    {
        [Test]
        public async Task DeleteHostnameBinding()
        {
            HostnamePortKey key = await GetFreeHostnameBindingKey();
            TrackBindingKey(key);
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = key,
                certhash = TestingCertThumbprint,
                appid = CreateTestAppId(),
                certstorename = StoreName.My.ToString(),
            });

            var configuration = new SslBindingConfiguration();
            configuration.Delete(key);

            Assert.That(await CertConfigCmd.BindingIsPresentInConfig(key), Is.False);
        }

        [Test]
        public async Task DeleteCcsBinding()
        {
            CcsPortKey key = await GetFreeCcsPortKey();
            TrackBindingKey(key);
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = key,
                appid = CreateTestAppId(),
            });

            var configuration = new SslBindingConfiguration();
            configuration.Delete(key);

            Assert.That(await CertConfigCmd.BindingIsPresentInConfig(key), Is.False);
        }

        [Test]
        public async Task DeleteScopedCcsBinding()
        {
            ScopedCcsKey key = await GetFreeScopedCcsKey("ssl-cert-binding.net.com");
            TrackBindingKey(key);
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                key = key,
                appid = CreateTestAppId(),
            });

            var configuration = new SslBindingConfiguration();
            configuration.Delete(key);

            Assert.That(await CertConfigCmd.BindingIsPresentInConfig(key), Is.False);
        }

        [Test]
        public async Task DeleteManyMixedFamilies()
        {
            IpPortKey ipKey = await GetFreeIpPortKey("::");
            HostnamePortKey hostnameKey = await GetFreeHostnameBindingKey("ssl-cert-binding.net.com");
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
            configuration.Delete(new SslBindingKey[] { ipKey, hostnameKey, ccsKey, scopedCcsKey });

            bool ipPresent = await CertConfigCmd.BindingIsPresentInConfig(ipKey);
            bool hostnamePresent = await CertConfigCmd.BindingIsPresentInConfig(hostnameKey);
            bool ccsPresent = await CertConfigCmd.BindingIsPresentInConfig(ccsKey);
            bool scopedCcsPresent = await CertConfigCmd.BindingIsPresentInConfig(scopedCcsKey);

            Assert.Multiple(() =>
            {
                Assert.That(ipPresent, Is.False);
                Assert.That(hostnamePresent, Is.False);
                Assert.That(ccsPresent, Is.False);
                Assert.That(scopedCcsPresent, Is.False);
            });
        }
    }
}
