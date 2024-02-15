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
            var ipPort = await GetEndpointWithFreeRandomPort(ip);
            var appId = Guid.NewGuid();

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort,
                certhash = _testingCertThumbprint,
                appid = appId,
                certstorename = null,
            });

            var config = new CertificateBindingConfiguration();
            var bindingsByIpPort = config.Query(ipPort);
            Assert.That(bindingsByIpPort.Count, Is.EqualTo(1));
            var binding = bindingsByIpPort[0];
            Assert.That(binding.AppId, Is.EqualTo(appId));
            Assert.That(binding.IpPort, Is.EqualTo(ipPort));
            Assert.That(binding.StoreName, Is.EqualTo("MY"));
            Assert.That(binding.Thumbprint, Is.EqualTo(_testingCertThumbprint));
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
        }

        [Test]
        public void QueryNone()
        {
            var notFoundIpPort = new IPEndPoint(0, IPEndPoint.MaxPort);
            var config = new CertificateBindingConfiguration();
            var bindingsByIpPort = config.Query(notFoundIpPort);
            Assert.That(bindingsByIpPort.Count, Is.EqualTo(0));
        }

        [Test]
        public async Task QueryAll()
        {
            var ipPort1 = await GetEndpointWithFreeRandomPort();
            var appId1 = Guid.NewGuid();
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort1,
                certhash = _testingCertThumbprint,
                appid = appId1,
                certstorename = StoreName.My.ToString(),
            });

            var ipPort2 = await GetEndpointWithFreeRandomPort();
            var appId2 = Guid.NewGuid();
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort2,
                certhash = _testingCertThumbprint,
                appid = appId2,
                certstorename = StoreName.AuthRoot.ToString(),
                clientcertnegotiation = true,
                revocationfreshnesstime = 100,
                usagecheck = false,
                verifyrevocationwithcachedclientcertonly = true,
            });


            var config = new CertificateBindingConfiguration();
            var allBindings = config.Query();
            var addedBindings = allBindings.Where(b => b.IpPort.Equals(ipPort1) || b.IpPort.Equals(ipPort2)).ToArray();
            Assert.That(addedBindings.Length, Is.EqualTo(2));
            var binding1 = addedBindings[0];
            Assert.That(binding1.AppId, Is.EqualTo(appId1));
            Assert.That(binding1.IpPort, Is.EqualTo(ipPort1));
            Assert.That(binding1.StoreName, Is.EqualTo(StoreName.My.ToString()));
            Assert.That(binding1.Thumbprint, Is.EqualTo(_testingCertThumbprint));
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

            var binding2 = addedBindings[1];
            Assert.That(binding2.AppId, Is.EqualTo(appId2));
            Assert.That(binding2.IpPort, Is.EqualTo(ipPort2));
            Assert.That(binding2.StoreName, Is.EqualTo(StoreName.AuthRoot.ToString()));
            Assert.That(binding2.Thumbprint, Is.EqualTo(_testingCertThumbprint));
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
        }

        [Test]
        public async Task AddWithDefaultOptions()
        {
            var ipPort = await GetEndpointWithFreeRandomPort();
            var appId = Guid.NewGuid();
                
            var configuration = new CertificateBindingConfiguration();
            configuration.Bind(new CertificateBinding(_testingCertThumbprint, StoreName.My, ipPort, appId));

            var result = await CertConfigCmd.Show(ipPort);
            Assert.That(result.IsSuccessfull, Is.True);
            var expectedOutput = string.Format(CultureInfo.InvariantCulture,
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
                ipPort, _testingCertThumbprint, appId.ToString("B"));

            AssertOutput(result.Output, expectedOutput);
        }

        [Test]
        public async Task AddWithNonDefaultOptions()
        {
            var ipPort = await GetEndpointWithFreeRandomPort();
            var appId = Guid.NewGuid();

            var configuration = new CertificateBindingConfiguration();

            var binding = new CertificateBinding(_testingCertThumbprint, StoreName.My, ipPort, appId, new BindingOptions
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

            var result = await CertConfigCmd.Show(ipPort);
            Assert.That(result.IsSuccessfull, Is.True);
            var expectedOutput = string.Format(CultureInfo.InvariantCulture,
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
                ipPort, _testingCertThumbprint, appId.ToString("B"));

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

            var ex = Assert.Throws<ArgumentNullException>(delete);
            Assert.That(ex.Message, Does.StartWith("Value cannot be null."));
            Assert.That(ex.ParamName, Is.EqualTo("endPoints"));
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
            var ipPort = await GetEndpointWithFreeRandomPort();
            var appId = Guid.NewGuid();

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort,
                certhash = _testingCertThumbprint,
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
            var ipPort1 = await GetEndpointWithFreeRandomPort();

            var appId1 = Guid.NewGuid();
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort1,
                certhash = _testingCertThumbprint,
                appid = appId1,
            });

            var ipPort2 = await GetEndpointWithFreeRandomPort();

            var appId2 = Guid.NewGuid();
            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort2,
                certhash = _testingCertThumbprint,
                appid = appId2,
            });

            var config = new CertificateBindingConfiguration();
            config.Delete(new[] { ipPort1, ipPort2 });
            Assert.That(await CertConfigCmd.IpPortIsPresentInConfig(ipPort1), Is.False);
            Assert.That(await CertConfigCmd.IpPortIsPresentInConfig(ipPort2), Is.False);
        }

        [Test]
        public async Task UpdateAsync()
        {
            var ipPort = await GetEndpointWithFreeRandomPort();
            var appId = Guid.NewGuid();

            await CertConfigCmd.Add(new CertConfigCmd.Options
            {
                ipport = ipPort,
                certhash = _testingCertThumbprint,
                appid = appId,
                certstorename = StoreName.AuthRoot.ToString(),
            });

            var configuration = new CertificateBindingConfiguration();

            var binding = new CertificateBinding(_testingCertThumbprint, StoreName.My, ipPort, appId, new BindingOptions
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

            var result = await CertConfigCmd.Show(ipPort);
            Assert.That(result.IsSuccessfull, Is.True);
            var expectedOutput = string.Format(CultureInfo.InvariantCulture,
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
                ipPort, _testingCertThumbprint, appId.ToString("B"));

            AssertOutput(result.Output, expectedOutput);
        }


        private static string _testingCertThumbprint = string.Empty;

        [SetUp]
        public void TestInitialize()
        {
            Assert.That(WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid), Is.True, "These unit-tests shoud run with Adminstrator permissions.");

            DoInLocalMachineCertStores(certStore =>
            {
                var cert = new X509Certificate2(Resources.certCA, string.Empty, X509KeyStorageFlags.MachineKeySet);
                _testingCertThumbprint = cert.Thumbprint;
                certStore.Add(cert);
            });
        }

        [TearDown]
        public async Task TestCleanup()
        {
            await CertConfigCmd.RemoveIpEndPoints(_testingCertThumbprint);
            DoInLocalMachineCertStores(certStore =>
            {
                var certs = certStore.Certificates.Find(X509FindType.FindByThumbprint, _testingCertThumbprint, false);
                certStore.RemoveRange(certs);
            });
            _testingCertThumbprint = string.Empty;
        }

        private static void DoInLocalMachineCertStores(Action<X509Store> action)
        {
            var storeNames = new[] { StoreName.My, StoreName.AuthRoot, };
            foreach (var storeName in storeNames)
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
            string actualAdjOutput = regEx.Replace(actualOutput, " ").Trim();
            string expectedAdjOutput = regEx.Replace(expectedOutput, " ").Trim();
            Assert.That(actualAdjOutput, Does.Contain(expectedAdjOutput).IgnoreCase);
        }
    }
}
