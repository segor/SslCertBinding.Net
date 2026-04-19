using System;
using System.Net;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    public class CertConfigCmdTests
    {
        [Test]
        public void CreateAddCommandOmitsCertificateArgumentsForCcsFamilies()
        {
            string ccsCommand = CertConfigCmd.CreateAddCommand(new CertConfigCmd.Options
            {
                key = new CcsPortKey(443),
                certhash = "001122",
                certstorename = "MY",
                appid = Guid.Parse("11111111-1111-1111-1111-111111111111"),
            });
            string scopedCcsCommand = CertConfigCmd.CreateAddCommand(new CertConfigCmd.Options
            {
                key = new ScopedCcsKey("example.com", 443),
                certhash = "001122",
                certstorename = "MY",
                appid = Guid.Parse("22222222-2222-2222-2222-222222222222"),
            });

            Assert.Multiple(() =>
            {
                Assert.That(ccsCommand, Does.Contain("http add sslcert ccs=443"));
                Assert.That(scopedCcsCommand, Does.Contain("http add sslcert scopedccs=example.com:443"));
                Assert.That(ccsCommand, Does.Not.Contain("certhash="));
                Assert.That(scopedCcsCommand, Does.Not.Contain("certhash="));
                Assert.That(ccsCommand, Does.Not.Contain("certstorename="));
                Assert.That(scopedCcsCommand, Does.Not.Contain("certstorename="));
            });
        }

        [Test]
        public void CreateAddCommandKeepsCertificateArgumentsForCertificateBackedFamilies()
        {
            string ipCommand = CertConfigCmd.CreateAddCommand(new CertConfigCmd.Options
            {
                key = new IpPortKey(IPAddress.Parse("0.0.0.0"), 443),
                certhash = "001122",
                certstorename = "AuthRoot",
                appid = Guid.Parse("33333333-3333-3333-3333-333333333333"),
            });
            string hostnameCommand = CertConfigCmd.CreateAddCommand(new CertConfigCmd.Options
            {
                key = new HostnamePortKey("example.com", 443),
                certhash = "aabbcc",
                appid = Guid.Parse("44444444-4444-4444-4444-444444444444"),
            });

            Assert.Multiple(() =>
            {
                Assert.That(ipCommand, Does.Contain("certhash=001122"));
                Assert.That(ipCommand, Does.Contain("certstorename=AuthRoot"));
                Assert.That(hostnameCommand, Does.Contain("certhash=aabbcc"));
                Assert.That(hostnameCommand, Does.Contain("certstorename=MY"));
            });
        }
    }
}
