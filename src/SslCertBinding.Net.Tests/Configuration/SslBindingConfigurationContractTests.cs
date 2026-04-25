using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public class SslBindingConfigurationContractTests
    {
        [Test]
        public void FindByIpKeyRejectsNull()
        {
            var configuration = new SslBindingConfiguration();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Find((IpPortKey)null));
            Assert.That(ex.ParamName, Is.EqualTo("key"));
        }

        [Test]
        public void FindByHostnameKeyRejectsNull()
        {
            var configuration = new SslBindingConfiguration();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Find((HostnamePortKey)null));
            Assert.That(ex.ParamName, Is.EqualTo("key"));
        }

        [Test]
        public void FindByUntypedKeyRejectsNull()
        {
            var configuration = new SslBindingConfiguration();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Find((SslBindingKey)null));
            Assert.That(ex.ParamName, Is.EqualTo("key"));
        }

        [Test]
        public void FindByUntypedIpKeyDispatchesToIpFind()
        {
            var configuration = new SslBindingConfiguration();

            ISslBinding result = configuration.Find((SslBindingKey)new IpPortKey(IPAddress.Any, 65535));

            Assert.That(result, Is.Null);
        }

        [Test]
        public void FindByUntypedHostnameKeyDispatchesToHostnameFind()
        {
            var configuration = new SslBindingConfiguration();

            ISslBinding result = configuration.Find((SslBindingKey)new HostnamePortKey("localhost", 65535));

            Assert.That(result, Is.Null);
        }

        [Test]
        public void FindByCcsKeyRejectsNull()
        {
            var configuration = new SslBindingConfiguration();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Find((CcsPortKey)null));
            Assert.That(ex.ParamName, Is.EqualTo("key"));
        }

        [Test]
        public void FindByScopedCcsKeyRejectsNull()
        {
            var configuration = new SslBindingConfiguration();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Find((ScopedCcsKey)null));
            Assert.That(ex.ParamName, Is.EqualTo("key"));
        }

        [Test]
        public void FindByUntypedCcsKeyDispatchesToCcsFind()
        {
            var configuration = new SslBindingConfiguration();

            ISslBinding result = configuration.Find((SslBindingKey)new CcsPortKey(65535));

            Assert.That(result, Is.Null);
        }

        [Test]
        public void FindByUntypedScopedCcsKeyDispatchesToScopedCcsFind()
        {
            var configuration = new SslBindingConfiguration();

            ISslBinding result = configuration.Find((SslBindingKey)new ScopedCcsKey("localhost", 65535));

            Assert.That(result, Is.Null);
        }

        [Test]
        public void FindByIpEndPointUsesImplicitKeyConversion()
        {
            var configuration = new SslBindingConfiguration();
            var endPoint = new IPEndPoint(IPAddress.Any, 65535);

            IpPortBinding result = configuration.Find(endPoint.ToSslBindingKey());

            Assert.That(result, Is.Null);
        }

        [Test]
        public void FindByDnsEndPointUsesImplicitKeyConversion()
        {
            var configuration = new SslBindingConfiguration();
            var endPoint = new DnsEndPoint("localhost", 65535);

            HostnamePortBinding result = configuration.Find(endPoint.ToHostnamePortKey());

            Assert.That(result, Is.Null);
        }

        [Test]
        public void FindByDnsEndPointUsesScopedCcsKeyConversion()
        {
            var configuration = new SslBindingConfiguration();
            var endPoint = new DnsEndPoint("localhost", 65535);

            ScopedCcsBinding result = configuration.Find(endPoint.ToScopedCcsKey());

            Assert.That(result, Is.Null);
        }

        [Test]
        public void UpsertRejectsNullBinding()
        {
            var configuration = new SslBindingConfiguration();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Upsert(null));
            Assert.That(ex.ParamName, Is.EqualTo("binding"));
        }

        [Test]
        public void DeleteRejectsNullKey()
        {
            var configuration = new SslBindingConfiguration();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Delete((SslBindingKey)null));
            Assert.That(ex.ParamName, Is.EqualTo("key"));
        }

        [Test]
        public void DeleteRejectsNullKeyCollection()
        {
            var configuration = new SslBindingConfiguration();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => configuration.Delete((IReadOnlyCollection<SslBindingKey>)null));
            Assert.That(ex.ParamName, Is.EqualTo("keys"));
        }

        [Test]
        public void DeleteAcceptsEmptyKeyCollection()
        {
            var configuration = new SslBindingConfiguration();

            Assert.DoesNotThrow(() => configuration.Delete(Array.Empty<SslBindingKey>()));
        }

        [Test]
        public void DeleteRejectsCollectionContainingNullItem()
        {
            var configuration = new SslBindingConfiguration();
            SslBindingKey[] keys = { new IpPortKey(IPAddress.Any, 65535), null };

            ArgumentException ex = Assert.Throws<ArgumentException>(() => configuration.Delete(keys));
            Assert.That(ex.ParamName, Is.EqualTo("keys"));
        }

        [Test]
        public void QueryByUnsupportedBindingTypeThrows()
        {
            var configuration = new SslBindingConfiguration();

            NotSupportedException ex = Assert.Throws<NotSupportedException>(() => configuration.Query<UnsupportedSslBinding>());
            Assert.That(ex.Message, Does.Contain(typeof(UnsupportedSslBinding).FullName));
        }

        [Test]
        public void FindByUnsupportedKeyTypeThrows()
        {
            var configuration = new SslBindingConfiguration();

            NotSupportedException ex = Assert.Throws<NotSupportedException>(() => configuration.Find(new UnsupportedBindingKey("unsupported")));
            Assert.That(ex.Message, Does.Contain(typeof(UnsupportedBindingKey).FullName));
        }

        [Test]
        public void UpsertUnsupportedBindingTypeThrows()
        {
            var configuration = new SslBindingConfiguration();

            NotSupportedException ex = Assert.Throws<NotSupportedException>(() => configuration.Upsert(new UnsupportedSslBinding(new UnsupportedBindingKey("unsupported"))));
            Assert.That(ex.Message, Does.Contain(typeof(UnsupportedSslBinding).FullName));
        }

        [Test]
        public void DeleteUnsupportedKeyTypeThrows()
        {
            var configuration = new SslBindingConfiguration();

            NotSupportedException ex = Assert.Throws<NotSupportedException>(() => configuration.Delete(new UnsupportedBindingKey("unsupported")));
            Assert.That(ex.Message, Does.Contain(typeof(UnsupportedBindingKey).FullName));
        }

        [Test]
        public void ToSslBindingKeyReturnsNullForNullIpEndPoint()
        {
            IPEndPoint endPoint = null;

            Assert.That(endPoint.ToSslBindingKey(), Is.Null);
        }

        [Test]
        public void ToHostnamePortKeyReturnsNullForNullDnsEndPoint()
        {
            DnsEndPoint endPoint = null;

            Assert.That(endPoint.ToHostnamePortKey(), Is.Null);
        }

        [Test]
        public void ToScopedCcsKeyReturnsNullForNullDnsEndPoint()
        {
            DnsEndPoint endPoint = null;

            Assert.That(endPoint.ToScopedCcsKey(), Is.Null);
        }

        [Test]
        public void OverrideUnsupportedRejectsIpPort()
        {
            ArgumentException ex = Assert.Throws<ArgumentException>(() => SslBindingConfiguration.OverrideUnsupported(SslBindingKind.IpPort, true));

            Assert.That(ex.ParamName, Is.EqualTo("kind"));
        }

        [TearDown]
        public void TearDown()
        {
            SslBindingConfiguration.OverrideUnsupported(SslBindingKind.HostnamePort, false);
            SslBindingConfiguration.OverrideUnsupported(SslBindingKind.CcsPort, false);
            SslBindingConfiguration.OverrideUnsupported(SslBindingKind.ScopedCcs, false);
        }

        [Test]
        public void QuerySkipsHostnameBindingsWhenSniIsNotSupported()
        {
            ConfigureUnsupportedSni();
            var configuration = new SslBindingConfiguration();

            IReadOnlyList<ISslBinding> result = configuration.Query();

            Assert.That(result.OfType<HostnamePortBinding>(), Is.Empty);
        }

        [Test]
        public void FindByHostnameKeyThrowsPlatformNotSupportedWhenSniIsNotSupported()
        {
            ConfigureUnsupportedSni();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Find(new HostnamePortKey("localhost", 443)),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void QueryByHostnameBindingTypeThrowsPlatformNotSupportedWhenSniIsNotSupported()
        {
            ConfigureUnsupportedSni();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Query<HostnamePortBinding>(),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void UpsertHostnameBindingThrowsPlatformNotSupportedWhenSniIsNotSupported()
        {
            ConfigureUnsupportedSni();
            var configuration = new SslBindingConfiguration();
            var binding = new HostnamePortBinding(
                new HostnamePortKey("localhost", 443),
                new SslCertificateReference("98BC1AACBC38F564B95E1499FA2BA0FC30899A3E", "MY"),
                Guid.Empty);

            Assert.That(
                () => configuration.Upsert(binding),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void DeleteHostnameBindingThrowsPlatformNotSupportedWhenSniIsNotSupported()
        {
            ConfigureUnsupportedSni();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Delete(new HostnamePortKey("localhost", 443)),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void QuerySkipsCcsBindingsWhenCcsIsNotSupported()
        {
            ConfigureUnsupportedCcs();
            var configuration = new SslBindingConfiguration();

            IReadOnlyList<ISslBinding> result = configuration.Query();

            Assert.That(result.OfType<CcsPortBinding>(), Is.Empty);
        }

        [Test]
        public void FindByCcsKeyThrowsPlatformNotSupportedWhenCcsIsNotSupported()
        {
            ConfigureUnsupportedCcs();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Find(new CcsPortKey(443)),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void QueryByCcsBindingTypeThrowsPlatformNotSupportedWhenCcsIsNotSupported()
        {
            ConfigureUnsupportedCcs();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Query<CcsPortBinding>(),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void UpsertCcsBindingThrowsPlatformNotSupportedWhenCcsIsNotSupported()
        {
            ConfigureUnsupportedCcs();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Upsert(new CcsPortBinding(new CcsPortKey(443), Guid.Empty)),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void UpsertCcsBindingRejectsNonDefaultBindingOptions()
        {
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Upsert(new CcsPortBinding(
                    new CcsPortKey(443),
                    Guid.Empty,
                    new BindingOptions { UseDsMappers = true })),
                Throws.TypeOf<NotSupportedException>()
                    .With.Message.Contains("BindingOptions"));
        }

        [Test]
        public void DeleteCcsBindingThrowsPlatformNotSupportedWhenCcsIsNotSupported()
        {
            ConfigureUnsupportedCcs();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Delete(new CcsPortKey(443)),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void QuerySkipsScopedCcsBindingsWhenScopedCcsIsNotSupported()
        {
            ConfigureUnsupportedScopedCcs();
            var configuration = new SslBindingConfiguration();

            IReadOnlyList<ISslBinding> result = configuration.Query();

            Assert.That(result.OfType<ScopedCcsBinding>(), Is.Empty);
        }

        [Test]
        public void FindByScopedCcsKeyThrowsPlatformNotSupportedWhenScopedCcsIsNotSupported()
        {
            ConfigureUnsupportedScopedCcs();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Find(new ScopedCcsKey("localhost", 443)),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void QueryByScopedCcsBindingTypeThrowsPlatformNotSupportedWhenScopedCcsIsNotSupported()
        {
            ConfigureUnsupportedScopedCcs();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Query<ScopedCcsBinding>(),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void UpsertScopedCcsBindingThrowsPlatformNotSupportedWhenScopedCcsIsNotSupported()
        {
            ConfigureUnsupportedScopedCcs();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Upsert(new ScopedCcsBinding(new ScopedCcsKey("localhost", 443), Guid.Empty)),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        [Test]
        public void DeleteScopedCcsBindingThrowsPlatformNotSupportedWhenScopedCcsIsNotSupported()
        {
            ConfigureUnsupportedScopedCcs();
            var configuration = new SslBindingConfiguration();

            Assert.That(
                () => configuration.Delete(new ScopedCcsKey("localhost", 443)),
                Throws.TypeOf<PlatformNotSupportedException>());
        }

        private sealed class UnsupportedBindingKey : SslBindingKey
        {
            public UnsupportedBindingKey(string value)
            {
                Value = value;
            }

            public string Value { get; }

            public override SslBindingKind Kind => (SslBindingKind)999;

            public override string ToString()
            {
                return Value;
            }
        }

        private sealed class UnsupportedSslBinding : SslBinding<UnsupportedBindingKey>
        {
            public UnsupportedSslBinding(UnsupportedBindingKey key)
                : base(Guid.Empty)
            {
                Key = key;
            }

            public override SslBindingKind Kind => (SslBindingKind)999;

            public override UnsupportedBindingKey Key { get; }
        }

        private static void ConfigureUnsupportedSni()
        {
            SslBindingConfiguration.OverrideUnsupported(SslBindingKind.HostnamePort, true);
        }

        private static void ConfigureUnsupportedCcs()
        {
            SslBindingConfiguration.OverrideUnsupported(SslBindingKind.CcsPort, true);
        }

        private static void ConfigureUnsupportedScopedCcs()
        {
            SslBindingConfiguration.OverrideUnsupported(SslBindingKind.ScopedCcs, true);
        }
    }
}
