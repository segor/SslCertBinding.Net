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
    [TestFixture]
    [NonParallelizable]
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public class CertificateBindingConfigurationTests
    {
        [TestCase("0.0.0.0")]
        [TestCase("::")]
        public async Task QueryOne(string ip)
        {
            IPEndPoint ipPort = await GetEndpointWithFreeRandomPort(ip);
            var appId = Guid.NewGuid();

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort,
                certhash = s_testingCertThumbprint,
                appid = appId,
                certstorename = null,
            });

            var config = new CertificateBindingConfiguration();
            IReadOnlyList<CertificateBinding> bindingsByIpPort = config.Query(ipPort);
            Assert.That(bindingsByIpPort, Has.Count.EqualTo(1));
            CertificateBinding binding = bindingsByIpPort[0];
            Assert.Multiple(() =>
            {
                Assert.That(binding.AppId, Is.EqualTo(appId));
                Assert.That(binding.IpPort, Is.EqualTo(ipPort));
                Assert.That(binding.StoreName, Is.EqualTo("MY"));
                Assert.That(binding.Thumbprint, Is.EqualTo(s_testingCertThumbprint));
                Assert.That(binding.Options.DoNotPassRequestsToRawFilters, Is.EqualTo(false));
                Assert.That(binding.Options.DoNotVerifyCertificateRevocation, Is.EqualTo(false));
                Assert.That(binding.Options.EnableRevocationFreshnessTime, Is.EqualTo(false));
                Assert.That(binding.Options.NegotiateCertificate, Is.EqualTo(false));
                Assert.That(binding.Options.NoUsageCheck, Is.EqualTo(false));
                Assert.That(binding.Options.RevocationFreshnessTime, Is.EqualTo(TimeSpan.Zero));
                Assert.That(binding.Options.RevocationUrlRetrievalTimeout, Is.EqualTo(TimeSpan.Zero));
                Assert.That(binding.Options.SslCtlIdentifier, Is.EqualTo(null));
                Assert.That(binding.Options.SslCtlStoreName, Is.EqualTo(null));
                Assert.That(binding.Options.UseDsMappers, Is.EqualTo(false));
                Assert.That(binding.Options.VerifyRevocationWithCachedCertificateOnly, Is.EqualTo(false));
            });
        }

        [Test]
        public void QueryNone()
        {
            var notFoundIpPort = new IPEndPoint(0, IPEndPoint.MaxPort);
            var config = new CertificateBindingConfiguration();
            IReadOnlyList<CertificateBinding> bindingsByIpPort = config.Query(notFoundIpPort);
            Assert.That(bindingsByIpPort, Is.Empty);
        }

        [Test]
        public async Task QueryAll()
        {
            IPEndPoint ipPort1 = await GetEndpointWithFreeRandomPort();
            var appId1 = Guid.NewGuid();
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort1,
                certhash = s_testingCertThumbprint,
                appid = appId1,
                certstorename = StoreName.My.ToString(),
            });

            IPEndPoint ipPort2 = await GetEndpointWithFreeRandomPort();
            var appId2 = Guid.NewGuid();
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort2,
                certhash = s_testingCertThumbprint,
                appid = appId2,
                certstorename = StoreName.AuthRoot.ToString(),
                clientcertnegotiation = true,
                revocationfreshnesstime = 100,
                usagecheck = false,
                verifyrevocationwithcachedclientcertonly = true,
            });


            var config = new CertificateBindingConfiguration();
            IReadOnlyList<CertificateBinding> allBindings = config.Query();
            List<CertificateBinding> addedBindings = allBindings.Where(b => b.IpPort.Equals(ipPort1) || b.IpPort.Equals(ipPort2)).ToList();
            Assert.That(addedBindings, Has.Count.EqualTo(2));
            CertificateBinding binding1 = addedBindings[0];
            Assert.Multiple(() =>
            {
                Assert.That(binding1.AppId, Is.EqualTo(appId1));
                Assert.That(binding1.IpPort, Is.EqualTo(ipPort1));
                Assert.That(binding1.StoreName, Is.EqualTo(StoreName.My.ToString()));
                Assert.That(binding1.Thumbprint, Is.EqualTo(s_testingCertThumbprint));
                Assert.That(binding1.Options.DoNotPassRequestsToRawFilters, Is.EqualTo(false));
                Assert.That(binding1.Options.DoNotVerifyCertificateRevocation, Is.EqualTo(false));
                Assert.That(binding1.Options.EnableRevocationFreshnessTime, Is.EqualTo(false));
                Assert.That(binding1.Options.NegotiateCertificate, Is.EqualTo(false));
                Assert.That(binding1.Options.NoUsageCheck, Is.EqualTo(false));
                Assert.That(binding1.Options.RevocationFreshnessTime, Is.EqualTo(TimeSpan.Zero));
                Assert.That(binding1.Options.RevocationUrlRetrievalTimeout, Is.EqualTo(TimeSpan.Zero));
                Assert.That(binding1.Options.SslCtlIdentifier, Is.EqualTo(null));
                Assert.That(binding1.Options.SslCtlStoreName, Is.EqualTo(null));
                Assert.That(binding1.Options.UseDsMappers, Is.EqualTo(false));
                Assert.That(binding1.Options.VerifyRevocationWithCachedCertificateOnly, Is.EqualTo(false));
            });

            CertificateBinding binding2 = addedBindings[1];
            Assert.Multiple(() =>
            {
                Assert.That(binding2.AppId, Is.EqualTo(appId2));
                Assert.That(binding2.IpPort, Is.EqualTo(ipPort2));
                Assert.That(binding2.StoreName, Is.EqualTo(StoreName.AuthRoot.ToString()));
                Assert.That(binding2.Thumbprint, Is.EqualTo(s_testingCertThumbprint));
                Assert.That(binding2.Options.DoNotPassRequestsToRawFilters, Is.EqualTo(false));
                Assert.That(binding2.Options.DoNotVerifyCertificateRevocation, Is.EqualTo(false));
                Assert.That(binding2.Options.EnableRevocationFreshnessTime, Is.EqualTo(true));
                Assert.That(binding2.Options.NegotiateCertificate, Is.EqualTo(true));
                Assert.That(binding2.Options.NoUsageCheck, Is.EqualTo(true));
                Assert.That(binding2.Options.RevocationFreshnessTime, Is.EqualTo(TimeSpan.FromSeconds(100)));
                Assert.That(binding2.Options.RevocationUrlRetrievalTimeout, Is.EqualTo(TimeSpan.Zero));
                Assert.That(binding2.Options.SslCtlIdentifier, Is.EqualTo(null));
                Assert.That(binding2.Options.SslCtlStoreName, Is.EqualTo(null));
                Assert.That(binding2.Options.UseDsMappers, Is.EqualTo(false));
                Assert.That(binding2.Options.VerifyRevocationWithCachedCertificateOnly, Is.EqualTo(true));
            });
        }

        [Test]
        public async Task AddWithDefaultOptions()
        {
            IPEndPoint ipPort = await GetEndpointWithFreeRandomPort();
            var appId = Guid.NewGuid();
                
            var configuration = new CertificateBindingConfiguration();
            configuration.Bind(new CertificateBinding(s_testingCertThumbprint, StoreName.My, ipPort, appId));

            CertConfigCmd.CommandResult result = await CertConfigCmd.Show(ipPort);
            Assert.That(result.IsSuccessfull, Is.True);
            string expectedOutput = string.Format(CultureInfo.InvariantCulture,
                @"  IP:port                 : {0} 
    Certificate Hash        : {1}
    Application ID          : {2} 
    Certificate Store Name  : My 
    Verify Client Certificate Revocation    : Enabled
    Verify Revocation Using Cached Client Certificate Only    : Disabled
    Usage Check    : Enabled
    Revocation Freshness Time : 0 
    URL Retrieval Timeout   : 0 
    Ctl Identifier          : (null) 
    Ctl Store Name          : (null) 
    DS Mapper Usage    : Disabled
    Negotiate Client Certificate    : Disabled",
                ipPort, s_testingCertThumbprint, appId.ToString("B"));

            AssertOutput(result.Output, expectedOutput);
        }

        [Test]
        public async Task AddWithNonDefaultOptions()
        {
            IPEndPoint ipPort = await GetEndpointWithFreeRandomPort();
            var appId = Guid.NewGuid();

            var configuration = new CertificateBindingConfiguration();

            var binding = new CertificateBinding(s_testingCertThumbprint, StoreName.My, ipPort, appId, new BindingOptions
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
            });

            configuration.Bind(binding);

            CertConfigCmd.CommandResult result = await CertConfigCmd.Show(ipPort);
            Assert.That(result.IsSuccessfull, Is.True);
            string expectedOutput = string.Format(CultureInfo.InvariantCulture,
                @"  IP:port                 : {0} 
    Certificate Hash        : {1}
    Application ID          : {2} 
    Certificate Store Name  : My 
    Verify Client Certificate Revocation    : Disabled
    Verify Revocation Using Cached Client Certificate Only    : Enabled
    Usage Check    : Disabled
    Revocation Freshness Time : 60 
    URL Retrieval Timeout   : 5000 
    Ctl Identifier          : (null) 
    Ctl Store Name          : (null) 
    DS Mapper Usage    : Enabled
    Negotiate Client Certificate    : Enabled",
                ipPort, s_testingCertThumbprint, appId.ToString("B"));

            AssertOutput(result.Output, expectedOutput);
        }

        [Test]
        public void DeleteNullCollectionArgument()
        {
            void delete()
            {
                var config = new CertificateBindingConfiguration();
                config.Delete((IReadOnlyCollection<IPEndPoint>)null);
            }

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delete);
            Assert.Multiple(() =>
            {
                Assert.That(ex.Message, Does.StartWith("Value cannot be null."));
                Assert.That(ex.ParamName, Is.EqualTo("endPoints"));
            });
        }

        [Test]
        public void DeleteEmptyCollectionArgument()
        {
            var config = new CertificateBindingConfiguration();
            config.Delete(Array.Empty<IPEndPoint>());
        }

        [Test]
        public async Task DeleteOne()
        {
            IPEndPoint ipPort = await GetEndpointWithFreeRandomPort();
            var appId = Guid.NewGuid();

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort,
                certhash = s_testingCertThumbprint,
                appid = appId,
                certstorename = null,
            });

            var config = new CertificateBindingConfiguration();
            config.Delete(ipPort);
            Assert.That(await CertConfigCmd.IpPortIsPresentInConfig(ipPort), Is.False);
        }

        [Test]
        public async Task DeleteMany()
        {
            IPEndPoint ipPort1 = await GetEndpointWithFreeRandomPort();

            var appId1 = Guid.NewGuid();
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort1,
                certhash = s_testingCertThumbprint,
                appid = appId1,
            });

            IPEndPoint ipPort2 = await GetEndpointWithFreeRandomPort();

            var appId2 = Guid.NewGuid();
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort2,
                certhash = s_testingCertThumbprint,
                appid = appId2,
            });

            var config = new CertificateBindingConfiguration();
            config.Delete(new[] { ipPort1, ipPort2 });
            Assert.Multiple(async () =>
            {
                Assert.That(await CertConfigCmd.IpPortIsPresentInConfig(ipPort1), Is.False);
                Assert.That(await CertConfigCmd.IpPortIsPresentInConfig(ipPort2), Is.False);
            });
        }

        [Test]
        public async Task UpdateAsync()
        {
            IPEndPoint ipPort = await GetEndpointWithFreeRandomPort();
            var appId = Guid.NewGuid();

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort,
                certhash = s_testingCertThumbprint,
                appid = appId,
                certstorename = StoreName.AuthRoot.ToString(),
            });

            var configuration = new CertificateBindingConfiguration();

            var binding = new CertificateBinding(s_testingCertThumbprint, StoreName.My, ipPort, appId, new BindingOptions
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
            });

            configuration.Bind(binding);

            CertConfigCmd.CommandResult result = await CertConfigCmd.Show(ipPort);
            Assert.That(result.IsSuccessfull, Is.True);
            string expectedOutput = string.Format(CultureInfo.InvariantCulture,
                @"  IP:port                 : {0} 
    Certificate Hash        : {1}
    Application ID          : {2} 
    Certificate Store Name  : My 
    Verify Client Certificate Revocation    : Disabled
    Verify Revocation Using Cached Client Certificate Only    : Enabled
    Usage Check    : Disabled
    Revocation Freshness Time : 60 
    URL Retrieval Timeout   : 5000 
    Ctl Identifier          : (null) 
    Ctl Store Name          : (null) 
    DS Mapper Usage    : Enabled
    Negotiate Client Certificate    : Enabled",
                ipPort, s_testingCertThumbprint, appId.ToString("B"));

            AssertOutput(result.Output, expectedOutput);
        }


        private static string s_testingCertThumbprint = string.Empty;

        [SetUp]
        public void TestInitialize()
        {
            Assert.That(WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid), Is.True, "These unit-tests shoud run with Adminstrator permissions.");

            DoInLocalMachineCertStores(certStore =>
            {
                var cert = new X509Certificate2(Resources.certCA, string.Empty, X509KeyStorageFlags.MachineKeySet);
                s_testingCertThumbprint = cert.Thumbprint;
                certStore.Add(cert);
            });
        }

        [TearDown]
        public async Task TestCleanup()
        {
            await CertConfigCmd.RemoveIpEndPoints(s_testingCertThumbprint);
            DoInLocalMachineCertStores(certStore =>
            {
                X509Certificate2Collection certs = certStore.Certificates.Find(X509FindType.FindByThumbprint, s_testingCertThumbprint, false);
                certStore.RemoveRange(certs);
            });
            s_testingCertThumbprint = string.Empty;
        }

        private static void DoInLocalMachineCertStores(Action<X509Store> action)
        {
            StoreName[] storeNames = new[] { StoreName.My, StoreName.AuthRoot, };
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

        private static async Task<IPEndPoint> GetEndpointWithFreeRandomPort(string ip = "0.0.0.0")
        {
            for (int port = 50000; port < 65535; port++)
            {
                var ipPort = new IPEndPoint(IPAddress.Parse(ip), port);
                if (IpEndpointTools.IpEndpointIsAvailableForListening(ipPort))
                {
                    if (!(await CertConfigCmd.IpPortIsPresentInConfig(ipPort)))
                        return ipPort;
                }
            }

            return null;
        }

        private static void AssertOutput(string actualOutput, string expectedOutput)
        {
            var regEx = new Regex(@"\s+");
            string actualAdjOutput = actualOutput.Substring(Math.Max(0, actualOutput.IndexOf("IP:port", StringComparison.InvariantCultureIgnoreCase)));
            actualAdjOutput = regEx.Replace(actualAdjOutput, " ").Trim();
            string expectedAdjOutput = regEx.Replace(expectedOutput, " ").Trim();
            Assert.That(actualAdjOutput, Does.Contain(expectedAdjOutput).IgnoreCase);
        }
    }
}
