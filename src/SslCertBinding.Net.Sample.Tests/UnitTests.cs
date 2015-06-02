using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SslCertBinding.Net.Sample.Tests.Properties;

namespace SslCertBinding.Net.Sample.Tests
{
	[TestClass]
	public class UnitTests
	{
		[TestMethod]
		public void Query() {
			var ipPort = GetEndpointWithFreeRandomPort();
			var appId = Guid.NewGuid();

			CertConfigCmd.Add(new CertConfigCmd.Options {
				ipport = ipPort,
				certhash = _testingCertThumbprint,
				appid = appId,
				certstorename = null,
			});

			ICertificateBindingConfiguration config = new CertificateBindingConfiguration();
			var bindingsByIpPort = config.Query(ipPort);
			Assert.AreEqual(1, bindingsByIpPort.Length);
			Assert.AreEqual(appId, bindingsByIpPort[0].AppId);
			Assert.AreEqual(ipPort, bindingsByIpPort[0].IpPort);
			Assert.AreEqual("MY", bindingsByIpPort[0].StoreName);
			Assert.AreEqual(_testingCertThumbprint, bindingsByIpPort[0].Thumbprint);
			Assert.AreEqual(false, bindingsByIpPort[0].Options.DoNotPassRequestsToRawFilters);
			Assert.AreEqual(false, bindingsByIpPort[0].Options.DoNotVerifyCertificateRevocation);
			Assert.AreEqual(false, bindingsByIpPort[0].Options.EnableRevocationFreshnessTime);
			Assert.AreEqual(false, bindingsByIpPort[0].Options.NegotiateCertificate);
			Assert.AreEqual(false, bindingsByIpPort[0].Options.NoUsageCheck);
			Assert.AreEqual(TimeSpan.Zero, bindingsByIpPort[0].Options.RevocationFreshnessTime);
			Assert.AreEqual(TimeSpan.Zero, bindingsByIpPort[0].Options.RevocationUrlRetrievalTimeout);
			Assert.AreEqual(null, bindingsByIpPort[0].Options.SslCtlIdentifier);
			Assert.AreEqual(null, bindingsByIpPort[0].Options.SslCtlStoreName);
			Assert.AreEqual(false, bindingsByIpPort[0].Options.UseDsMappers);
			Assert.AreEqual(false, bindingsByIpPort[0].Options.VerifyRevocationWithCachedCertificateOnly);
		}

		[TestMethod]
		public void AddWithDefaultOptions() {
			var ipPort = GetEndpointWithFreeRandomPort();
			var appId = Guid.NewGuid();

			ICertificateBindingConfiguration configuration = new CertificateBindingConfiguration();

			var updated = configuration.Bind(new CertificateBinding(_testingCertThumbprint, StoreName.My, ipPort, appId));

			Assert.IsFalse(updated);
			var result = CertConfigCmd.Show(ipPort);
			Assert.IsTrue(result.IsSuccessfull);
			var expectedOutput = string.Format(
@"    IP:port                 : {0} 
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
    Negotiate Client Certificate    : Disabled
"
				, ipPort, _testingCertThumbprint, appId.ToString("B"));
			Assert.IsTrue(result.Output.ToLowerInvariant().Contains(expectedOutput.ToLowerInvariant()));
		}

		[TestMethod]
		public void AddWithNonDefaultOptions() {
			var ipPort = GetEndpointWithFreeRandomPort();
			var appId = Guid.NewGuid();

			ICertificateBindingConfiguration configuration = new CertificateBindingConfiguration();

			var binding = new CertificateBinding(_testingCertThumbprint, StoreName.My, ipPort, appId, new BindingOptions() {
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

			var updated = configuration.Bind(binding);

			Assert.IsFalse(updated);
			var result = CertConfigCmd.Show(ipPort);
			Assert.IsTrue(result.IsSuccessfull);
			var expectedOutput = string.Format(
@"    IP:port                 : {0} 
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
    Negotiate Client Certificate    : Enabled
"
				, ipPort, _testingCertThumbprint, appId.ToString("B"));
			Assert.IsTrue(result.Output.ToLowerInvariant().Contains(expectedOutput.ToLowerInvariant()));
		}

		private static string _testingCertThumbprint = string.Empty;

		[TestInitialize]
		public void TestInitialize() {
			DoInCertStore(certStore => {
				var cert = new X509Certificate2(Resources.certCA, string.Empty);
				_testingCertThumbprint = cert.Thumbprint;
				certStore.Add(cert);
			});
		}

		[TestCleanup]
		public void TestCleanup() {
			CertConfigCmd.RemoveIpEndPoints(_testingCertThumbprint);
			DoInCertStore(certStore => {
				var certs = certStore.Certificates.Find(X509FindType.FindByThumbprint, _testingCertThumbprint, false);
				certStore.RemoveRange(certs);
			});
		}


		private static void DoInCertStore(Action<X509Store> action) {
			var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
			store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
			action(store);
			store.Close();
		}

		private static IPEndPoint GetEndpointWithFreeRandomPort(string ip = "0.0.0.0") {
			for (int port = 50000; port < 65535; port++) {
				var ipPort = new IPEndPoint(IPAddress.Parse(ip), port);
				if (IpEndpointTools.IpEndpointIsAvailableForListening(ipPort) && !CertConfigCmd.IpPortIsPresentInConfig(ipPort))
					return ipPort;
			}

			return null;
		}
	}
}
