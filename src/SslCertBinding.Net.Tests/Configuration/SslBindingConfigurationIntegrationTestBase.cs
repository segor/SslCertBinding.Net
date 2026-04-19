using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using NUnit.Framework;
using SslCertBinding.Net.Tests.Properties;

namespace SslCertBinding.Net.Tests
{
    [NonParallelizable]
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public abstract class SslBindingConfigurationIntegrationTestBase
    {
        private const X509KeyStorageFlags TestCertificateKeyStorageFlags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet;
        private const string TestAppIdPrefix = "a11ce55c";
        private readonly List<SslBindingKey> _trackedKeys = new();
        protected static string TestingCertThumbprint { get; private set; } = string.Empty;

        [SetUp]
        public async Task TestInitialize()
        {
            Assert.That(WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid), Is.True, "These unit-tests shoud run with Adminstrator permissions.");

            using (var cert = new X509Certificate2(Resources.certCA, string.Empty, TestCertificateKeyStorageFlags))
            {
                TestingCertThumbprint = cert.Thumbprint;
            }

            await RemoveTrackedFamilySafetyNetBindings();
            await CertConfigCmd.RemoveBindings(TestingCertThumbprint);

            DoInLocalMachineCertStores(
                certStore =>
                {
                    var cert = new X509Certificate2(Resources.certCA, string.Empty, TestCertificateKeyStorageFlags);
                    certStore.Add(cert);
                });
        }

        [TearDown]
        public async Task TestCleanup()
        {
            foreach (SslBindingKey key in _trackedKeys.Distinct().Reverse())
            {
                try
                {
                    await CertConfigCmd.Delete(key);
                }
                catch (InvalidOperationException)
                {
                }
            }

            await RemoveTrackedFamilySafetyNetBindings();
            await CertConfigCmd.RemoveBindings(TestingCertThumbprint);
            DoInLocalMachineCertStores(
                certStore =>
                {
                    X509Certificate2Collection certs = certStore.Certificates.Find(X509FindType.FindByThumbprint, TestingCertThumbprint, false);
                    certStore.RemoveRange(certs);
                });
            TestingCertThumbprint = string.Empty;
            _trackedKeys.Clear();
        }

        protected static void DoInLocalMachineCertStores(Action<X509Store> action)
        {
            StoreName[] storeNames = new[] { StoreName.My, StoreName.AuthRoot };
            foreach (StoreName storeName in storeNames)
            {
                var store = new X509Store(storeName, StoreLocation.LocalMachine);
                try
                {
                    store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                    action(store);
                }
                finally
                {
                    store.Close();
                }
            }
        }

        protected static async Task<IpPortKey> GetFreeIpPortKey(string ip = "0.0.0.0")
        {
            for (int port = 50000; port < 65535; port++)
            {
                var key = new IpPortKey(IPAddress.Parse(ip), port);
                if (IpEndpointTools.IpEndpointIsAvailableForListening(key.ToIPEndPoint())
                    && !(await CertConfigCmd.BindingIsPresentInConfig(key)))
                {
                    return key;
                }
            }

            return null;
        }

        protected static async Task<HostnamePortKey> GetFreeHostnameBindingKey(string host = "localhost")
        {
            for (int port = 50000; port < 65535; port++)
            {
                var key = new HostnamePortKey(host, port);
                if (IpEndpointTools.IpEndpointIsAvailableForListening(new IPEndPoint(IPAddress.Any, port))
                    && !(await CertConfigCmd.BindingIsPresentInConfig(key)))
                {
                    return key;
                }
            }

            return null;
        }

        protected static async Task<CcsPortKey> GetFreeCcsPortKey()
        {
            for (int port = 50000; port < 65535; port++)
            {
                var key = new CcsPortKey(port);
                if (IpEndpointTools.IpEndpointIsAvailableForListening(new IPEndPoint(IPAddress.Any, port))
                    && !(await CertConfigCmd.BindingIsPresentInConfig(key)))
                {
                    return key;
                }
            }

            return null;
        }

        protected static async Task<ScopedCcsKey> GetFreeScopedCcsKey(string host = "localhost")
        {
            for (int port = 50000; port < 65535; port++)
            {
                var key = new ScopedCcsKey(host, port);
                if (IpEndpointTools.IpEndpointIsAvailableForListening(new IPEndPoint(IPAddress.Any, port))
                    && !(await CertConfigCmd.BindingIsPresentInConfig(key)))
                {
                    return key;
                }
            }

            return null;
        }

        protected static async Task<SslBindingKey> GetFreeBindingKey(SslBindingKind kind, string value = null)
        {
            switch (kind)
            {
                case SslBindingKind.IpPort:
                    return await GetFreeIpPortKey(value ?? "0.0.0.0");
                case SslBindingKind.HostnamePort:
                    return await GetFreeHostnameBindingKey(value ?? "localhost");
                case SslBindingKind.CcsPort:
                    return await GetFreeCcsPortKey();
                case SslBindingKind.ScopedCcs:
                    return await GetFreeScopedCcsKey(value ?? "localhost");
                default:
                    throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        protected static ISslBinding CreateBinding(SslBindingKey key, Guid appId, BindingOptions options)
        {
            switch (key)
            {
                case IpPortKey ipKey:
                    return new IpPortBinding(ipKey, new SslCertificateReference(TestingCertThumbprint, StoreName.My), appId, options);
                case HostnamePortKey hostnameKey:
                    return new HostnamePortBinding(hostnameKey, new SslCertificateReference(TestingCertThumbprint, StoreName.My), appId, options);
                case CcsPortKey ccsKey:
                    return new CcsPortBinding(ccsKey, appId, options);
                case ScopedCcsKey scopedCcsKey:
                    return new ScopedCcsBinding(scopedCcsKey, appId, options);
                default:
                    throw new ArgumentOutOfRangeException(nameof(key));
            }
        }

        protected static ISslBinding QuerySingleBinding(SslBindingConfiguration configuration, SslBindingKey key)
        {
            switch (key)
            {
                case IpPortKey ipKey:
                    return configuration.Query(ipKey).Single();
                case HostnamePortKey hostnameKey:
                    return configuration.Query(hostnameKey).Single();
                case CcsPortKey ccsKey:
                    return configuration.Query(ccsKey).Single();
                case ScopedCcsKey scopedCcsKey:
                    return configuration.Query(scopedCcsKey).Single();
                default:
                    throw new ArgumentOutOfRangeException(nameof(key));
            }
        }

        protected static bool TryGetCertificate(ISslBinding binding, out SslCertificateReference certificate)
        {
            switch (binding)
            {
                case IpPortBinding ipBinding:
                    certificate = ipBinding.Certificate;
                    return true;
                case HostnamePortBinding hostnameBinding:
                    certificate = hostnameBinding.Certificate;
                    return true;
                default:
                    certificate = null;
                    return false;
            }
        }

        protected static BindingOptions CreateDefaultBindingOptions()
        {
            return new BindingOptions();
        }

        protected static BindingOptions CreateAllEnabledBindingOptions()
        {
            return new BindingOptions
            {
                RevocationFreshnessTime = TimeSpan.FromMinutes(7),
                RevocationUrlRetrievalTimeout = TimeSpan.FromSeconds(9),
                UseDsMappers = true,
                NegotiateCertificate = true,
                DoNotPassRequestsToRawFilters = true,
                DoNotVerifyCertificateRevocation = true,
                VerifyRevocationWithCachedCertificateOnly = true,
                EnableRevocationFreshnessTime = true,
                NoUsageCheck = true,
                DisableTls12 = true,
            };
        }

        protected static BindingOptions CreateMixedBindingOptions()
        {
            return new BindingOptions
            {
                RevocationFreshnessTime = TimeSpan.FromSeconds(30),
                RevocationUrlRetrievalTimeout = TimeSpan.FromMilliseconds(2500),
                UseDsMappers = true,
                NegotiateCertificate = false,
                DoNotPassRequestsToRawFilters = true,
                DoNotVerifyCertificateRevocation = false,
                VerifyRevocationWithCachedCertificateOnly = true,
                EnableRevocationFreshnessTime = true,
                NoUsageCheck = false,
                DisableTls12 = true,
            };
        }

        protected static BindingOptions CreateCcsMixedBindingOptions()
        {
            return CreateDefaultBindingOptions();
        }

        protected static BindingOptions CreateCcsAllEnabledBindingOptions()
        {
            return CreateDefaultBindingOptions();
        }

        protected static void AssertBindingOptions(BindingOptions actual, BindingOptions expected)
        {
            Assert.Multiple(() =>
            {
                Assert.That(actual.DoNotVerifyCertificateRevocation, Is.EqualTo(expected.DoNotVerifyCertificateRevocation));
                Assert.That(actual.VerifyRevocationWithCachedCertificateOnly, Is.EqualTo(expected.VerifyRevocationWithCachedCertificateOnly));
                Assert.That(actual.EnableRevocationFreshnessTime, Is.EqualTo(expected.EnableRevocationFreshnessTime));
                Assert.That(actual.NoUsageCheck, Is.EqualTo(expected.NoUsageCheck));
                Assert.That(actual.RevocationFreshnessTime, Is.EqualTo(expected.RevocationFreshnessTime));
                Assert.That(actual.RevocationUrlRetrievalTimeout, Is.EqualTo(expected.RevocationUrlRetrievalTimeout));
                Assert.That(actual.SslCtlIdentifier, Is.EqualTo(expected.SslCtlIdentifier));
                Assert.That(actual.SslCtlStoreName, Is.EqualTo(expected.SslCtlStoreName));
                Assert.That(actual.NegotiateCertificate, Is.EqualTo(expected.NegotiateCertificate));
                Assert.That(actual.UseDsMappers, Is.EqualTo(expected.UseDsMappers));
                Assert.That(actual.DoNotPassRequestsToRawFilters, Is.EqualTo(expected.DoNotPassRequestsToRawFilters));
                Assert.That(actual.DisableTls12, Is.EqualTo(expected.DisableTls12));
            });
        }

        protected static void AssertBindingMatches(ISslBinding binding, SslBindingKey expectedKey, Guid expectedAppId, BindingOptions expectedOptions, string expectedStoreName)
        {
            Assert.Multiple(() =>
            {
                Assert.That(binding.Key, Is.EqualTo(expectedKey));
                Assert.That(binding.AppId, Is.EqualTo(expectedAppId));
                bool hasCertificate = TryGetCertificate(binding, out SslCertificateReference certificate);
                if (expectedStoreName == null)
                {
                    Assert.That(hasCertificate, Is.False);
                }
                else
                {
                    Assert.That(hasCertificate, Is.True);
                    Assert.That(certificate.Thumbprint, Is.EqualTo(TestingCertThumbprint));
                    Assert.That(string.Equals(certificate.StoreName, expectedStoreName, StringComparison.OrdinalIgnoreCase), Is.True);
                }

                AssertBindingOptions(binding.Options, expectedOptions);
            });
        }

        protected void TrackBindingKey(SslBindingKey key)
        {
            if (key != null)
            {
                _trackedKeys.Add(key);
            }
        }

        protected static Guid CreateTestAppId()
        {
            string guid = Guid.NewGuid().ToString("D", CultureInfo.InvariantCulture);
            char[] chars = guid.ToCharArray();
            for (int index = 0; index < TestAppIdPrefix.Length; index++)
            {
                chars[index] = TestAppIdPrefix[index];
            }

            return Guid.Parse(new string(chars));
        }

        private static async Task RemoveTrackedFamilySafetyNetBindings()
        {
            CertConfigCmd.BindingRecord[] records = await CertConfigCmd.GetBindingRecords();
            foreach (SslBindingKey key in records.Where(IsTrackedFamilySafetyNetRecord).Select(record => record.Key))
            {
                try
                {
                    await CertConfigCmd.Delete(key);
                }
                catch (InvalidOperationException)
                {
                }
            }
        }

        private static bool IsTrackedFamilySafetyNetRecord(CertConfigCmd.BindingRecord record)
        {
            return record.Key != null
                && (record.Key is CcsPortKey || record.Key is ScopedCcsKey)
                && record.AppId.ToString("D", CultureInfo.InvariantCulture).StartsWith(TestAppIdPrefix, StringComparison.OrdinalIgnoreCase);
        }

        protected static bool IsTestAppId(Guid appId)
        {
            return appId.ToString("D", CultureInfo.InvariantCulture).StartsWith(TestAppIdPrefix, StringComparison.OrdinalIgnoreCase);
        }

        protected static bool IsTrackedFamilyKey(SslBindingKey key)
        {
            switch (key)
            {
                case CcsPortKey ccsKey:
                    return ccsKey.Port >= 50000;
                case ScopedCcsKey scopedCcsKey:
                    return scopedCcsKey.Port >= 50000;
                default:
                    return false;
            }
        }

        protected static void AssertOutput(string actualOutput, string expectedOutput)
        {
            var regex = new Regex(@"\s+");
            string normalizedActual = regex.Replace(actualOutput, " ").Trim();
            string normalizedExpected = regex.Replace(expectedOutput, " ").Trim();
            Assert.That(normalizedActual, Does.Contain(normalizedExpected).IgnoreCase);
        }
    }
}
