using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SslCertBinding.Net.Sample.Tests.Properties;

namespace SslCertBinding.Net.Sample.Tests
{
    [TestClass]
    [DoNotParallelize()]
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public class UnitTests
    {
        [TestMethod]
        public async Task QueryOne()
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
            var bindingsByIpPort = config.Query(ipPort);
            Assert.AreEqual(1, bindingsByIpPort.Count);
            var binding = bindingsByIpPort[0];
            Assert.AreEqual(appId, binding.AppId);
            Assert.AreEqual(ipPort, binding.IpPort);
            Assert.AreEqual("MY", binding.StoreName);
            Assert.AreEqual(_testingCertThumbprint, binding.Thumbprint);
            Assert.AreEqual(false, binding.Options.DoNotPassRequestsToRawFilters);
            Assert.AreEqual(false, binding.Options.DoNotVerifyCertificateRevocation);
            Assert.AreEqual(false, binding.Options.EnableRevocationFreshnessTime);
            Assert.AreEqual(false, binding.Options.NegotiateCertificate);
            Assert.AreEqual(false, binding.Options.NoUsageCheck);
            Assert.AreEqual(TimeSpan.Zero, binding.Options.RevocationFreshnessTime);
            Assert.AreEqual(TimeSpan.Zero, binding.Options.RevocationUrlRetrievalTimeout);
            Assert.AreEqual(null, binding.Options.SslCtlIdentifier);
            Assert.AreEqual(null, binding.Options.SslCtlStoreName);
            Assert.AreEqual(false, binding.Options.UseDsMappers);
            Assert.AreEqual(false, binding.Options.VerifyRevocationWithCachedCertificateOnly);
        }

        [TestMethod]
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
            Assert.AreEqual(2, addedBindings.Length);
            var binding1 = addedBindings[0];
            Assert.AreEqual(appId1, binding1.AppId);
            Assert.AreEqual(ipPort1, binding1.IpPort);
            Assert.AreEqual(StoreName.My.ToString(), binding1.StoreName);
            Assert.AreEqual(_testingCertThumbprint, binding1.Thumbprint);
            Assert.AreEqual(false, binding1.Options.DoNotPassRequestsToRawFilters);
            Assert.AreEqual(false, binding1.Options.DoNotVerifyCertificateRevocation);
            Assert.AreEqual(false, binding1.Options.EnableRevocationFreshnessTime);
            Assert.AreEqual(false, binding1.Options.NegotiateCertificate);
            Assert.AreEqual(false, binding1.Options.NoUsageCheck);
            Assert.AreEqual(TimeSpan.Zero, binding1.Options.RevocationFreshnessTime);
            Assert.AreEqual(TimeSpan.Zero, binding1.Options.RevocationUrlRetrievalTimeout);
            Assert.AreEqual(null, binding1.Options.SslCtlIdentifier);
            Assert.AreEqual(null, binding1.Options.SslCtlStoreName);
            Assert.AreEqual(false, binding1.Options.UseDsMappers);
            Assert.AreEqual(false, binding1.Options.VerifyRevocationWithCachedCertificateOnly);

            var binding2 = addedBindings[1];
            Assert.AreEqual(appId2, binding2.AppId);
            Assert.AreEqual(ipPort2, binding2.IpPort);
            Assert.AreEqual(StoreName.AuthRoot.ToString(), binding2.StoreName);
            Assert.AreEqual(_testingCertThumbprint, binding2.Thumbprint);
            Assert.AreEqual(false, binding2.Options.DoNotPassRequestsToRawFilters);
            Assert.AreEqual(false, binding2.Options.DoNotVerifyCertificateRevocation);
            Assert.AreEqual(true, binding2.Options.EnableRevocationFreshnessTime);
            Assert.AreEqual(true, binding2.Options.NegotiateCertificate);
            Assert.AreEqual(true, binding2.Options.NoUsageCheck);
            Assert.AreEqual(TimeSpan.FromSeconds(100), binding2.Options.RevocationFreshnessTime);
            Assert.AreEqual(TimeSpan.Zero, binding2.Options.RevocationUrlRetrievalTimeout);
            Assert.AreEqual(null, binding2.Options.SslCtlIdentifier);
            Assert.AreEqual(null, binding2.Options.SslCtlStoreName);
            Assert.AreEqual(false, binding2.Options.UseDsMappers);
            Assert.AreEqual(true, binding2.Options.VerifyRevocationWithCachedCertificateOnly);
        }

        [TestMethod]
        public async Task AddWithDefaultOptions()
        {
            var ipPort = await GetEndpointWithFreeRandomPort();
            var appId = Guid.NewGuid();

            var configuration = new CertificateBindingConfiguration();
            configuration.Bind(new CertificateBinding(_testingCertThumbprint, StoreName.My, ipPort, appId));

            var result = await CertConfigCmd.Show(ipPort);
            Assert.IsTrue(result.IsSuccessfull);
            var expectedOutput = string.Format(
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

        [TestMethod]
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
            Assert.IsTrue(result.IsSuccessfull);
            var expectedOutput = string.Format(
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

        [TestMethod]
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
            Assert.IsFalse(await CertConfigCmd.IpPortIsPresentInConfig(ipPort));
        }

        [TestMethod]
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
            Assert.IsFalse(await CertConfigCmd.IpPortIsPresentInConfig(ipPort1));
            Assert.IsFalse(await CertConfigCmd.IpPortIsPresentInConfig(ipPort2));
        }

        [TestMethod]
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
            Assert.IsTrue(result.IsSuccessfull);
            var expectedOutput = string.Format(
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

        [TestInitialize]
        public void TestInitialize()
        {
            Assert.IsTrue(WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid), "These unit-tests shoud run with Adminstrator permissions.");

            DoInLocalMachineCertStores(certStore => {
                var cert = new X509Certificate2(Resources.certCA, string.Empty, X509KeyStorageFlags.MachineKeySet);
                _testingCertThumbprint = cert.Thumbprint;
                certStore.Add(cert);
            });
        }

        [TestCleanup]
        public async Task TestCleanup()
        {
            await CertConfigCmd.RemoveIpEndPoints(_testingCertThumbprint);
            DoInLocalMachineCertStores(certStore => {
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
                try {
                    store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                    action(store);
                }
                finally {
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
                }            }

            return null;
        }

        private static void AssertOutput(string actualOutput, string expectedOutput)
        {
            Assert.IsTrue(actualOutput.ToLowerInvariant().Replace(" ", "")
                .Contains(expectedOutput.ToLowerInvariant().Replace(" ", "")));
        }
    }
}
