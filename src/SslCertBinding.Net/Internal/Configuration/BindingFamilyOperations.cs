using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SslCertBinding.Net.Internal.Interop;

namespace SslCertBinding.Net.Internal
{
#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    internal interface ISslBindingFamilyOperations
    {
        SslBindingKind Kind { get; }

        HttpApi.HTTP_SERVICE_CONFIG_ID ConfigId { get; }

        Type KeyType { get; }

        Type BindingType { get; }

        IReadOnlyList<ISslBinding> QueryAll();

        ISslBinding FindExact(SslBindingKey key);

        void Upsert(ISslBinding binding);

        void Delete(SslBindingKey key);

        bool ProbeSupport();
    }

#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    internal abstract class BindingFamilyOperations<TKey, TBinding, TSet> : ISslBindingFamilyOperations
        where TKey : SslBindingKey
        where TBinding : class, ISslBinding
        where TSet : struct
    {
        private readonly Func<TBinding, SafeInteropResult<TSet>> _createSetStruct;
        private readonly Func<TKey, SafeInteropResult<TSet>> _createDeleteStruct;

        protected BindingFamilyOperations(
            SslBindingKind kind,
            HttpApi.HTTP_SERVICE_CONFIG_ID configId,
            Func<TBinding, SafeInteropResult<TSet>> createSetStruct,
            Func<TKey, SafeInteropResult<TSet>> createDeleteStruct)
        {
            Kind = kind;
            ConfigId = configId;
            _createSetStruct = createSetStruct;
            _createDeleteStruct = createDeleteStruct;
        }

        public SslBindingKind Kind { get; }

        public HttpApi.HTTP_SERVICE_CONFIG_ID ConfigId { get; }

        public Type KeyType => typeof(TKey);

        public Type BindingType => typeof(TBinding);

        public IReadOnlyList<ISslBinding> QueryAll() => QueryAllCore().Cast<ISslBinding>().ToArray();

        public ISslBinding FindExact(SslBindingKey key)
        {
            TBinding binding = QueryExactCore((TKey)key);
            return binding;
        }

        public void Upsert(ISslBinding binding) => UpsertCore((TBinding)binding);

        public void Delete(SslBindingKey key) => DeleteCore((TKey)key);

        public abstract bool ProbeSupport();

        protected abstract IReadOnlyList<TBinding> QueryAllCore();

        protected abstract TBinding QueryExactCore(TKey key);

        protected virtual void UpsertCore(TBinding binding)
        {
            BindingFamilyInterop.UpsertStruct(ConfigId, _createSetStruct(binding));
        }

        protected virtual void DeleteCore(TKey key) =>
            BindingFamilyInterop.DeleteStruct(ConfigId, _createDeleteStruct(key));
    }

 #if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    internal sealed class IpPortBindingOperations : BindingFamilyOperations<IpPortKey, IpPortBinding, HttpApi.HTTP_SERVICE_CONFIG_SSL_SET>
    {
        public IpPortBindingOperations()
            : base(
                SslBindingKind.IpPort,
                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                BindingStructures.CreateSetStruct,
                BindingStructures.CreateDeleteStruct)
        {
        }

        public override bool ProbeSupport() => true;

        protected override IReadOnlyList<IpPortBinding> QueryAllCore() =>
            BindingFamilyInterop.QueryMany<HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY, HttpApi.HTTP_SERVICE_CONFIG_SSL_SET, IpPortBinding>(
                ConfigId,
                BindingStructures.CreateNextIpQuery,
                BindingStructures.MapIpBinding);

        protected override IpPortBinding QueryExactCore(IpPortKey key) =>
            BindingFamilyInterop.QuerySingle<HttpApi.HTTP_SERVICE_CONFIG_SSL_QUERY, HttpApi.HTTP_SERVICE_CONFIG_SSL_SET, IpPortBinding>(
                ConfigId,
                BindingStructures.CreateExactQuery(key),
                BindingStructures.MapIpBinding);

    }

#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    internal sealed class HostnamePortBindingOperations : BindingFamilyOperations<HostnamePortKey, HostnamePortBinding, HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET>
    {
        public HostnamePortBindingOperations()
            : base(
                SslBindingKind.HostnamePort,
                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo,
                BindingStructures.CreateSetStruct,
                BindingStructures.CreateDeleteStruct)
        {
        }

        public override bool ProbeSupport()
        {
            HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY query = BindingStructures.CreateNextHostnameQuery(0);
            IntPtr queryStructPtr = BindingFamilyInterop.StructureToPtr(query);
            return BindingFamilyInterop.ProbeSupport(
                ConfigId,
                new SafeInteropResult<IntPtr>(queryStructPtr, () => BindingFamilyInterop.FreeStructurePtr<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY>(queryStructPtr)),
                Marshal.SizeOf<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY>());
        }

        protected override IReadOnlyList<HostnamePortBinding> QueryAllCore() =>
            BindingFamilyInterop.QueryMany<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY, HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET, HostnamePortBinding>(
                ConfigId,
                BindingStructures.CreateNextHostnameQuery,
                BindingStructures.MapHostnameBinding);

        protected override HostnamePortBinding QueryExactCore(HostnamePortKey key) =>
            BindingFamilyInterop.QuerySingle<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY, HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET, HostnamePortBinding>(
                ConfigId,
                BindingStructures.CreateExactQuery(key),
                BindingStructures.MapHostnameBinding);

    }

#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    internal sealed class CcsPortBindingOperations : BindingFamilyOperations<CcsPortKey, CcsPortBinding, HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_SET>
    {
        public CcsPortBindingOperations()
            : base(
                SslBindingKind.CcsPort,
                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslCcsCertInfo,
                BindingStructures.CreateSetStruct,
                BindingStructures.CreateDeleteStruct)
        {
        }

        public override bool ProbeSupport()
        {
            HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_QUERY query = BindingStructures.CreateNextCcsQuery(0);
            IntPtr queryStructPtr = BindingFamilyInterop.StructureToPtr(query);
            return BindingFamilyInterop.ProbeSupport(
                ConfigId,
                new SafeInteropResult<IntPtr>(queryStructPtr, () => BindingFamilyInterop.FreeStructurePtr<HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_QUERY>(queryStructPtr)),
                Marshal.SizeOf<HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_QUERY>());
        }

        protected override IReadOnlyList<CcsPortBinding> QueryAllCore() =>
            BindingFamilyInterop.QueryMany<HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_QUERY, HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_SET, CcsPortBinding>(
                ConfigId,
                BindingStructures.CreateNextCcsQuery,
                BindingStructures.MapCcsBinding);

        protected override CcsPortBinding QueryExactCore(CcsPortKey key) =>
            BindingFamilyInterop.QuerySingle<HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_QUERY, HttpApi.HTTP_SERVICE_CONFIG_SSL_CCS_SET, CcsPortBinding>(
                ConfigId,
                BindingStructures.CreateExactQuery(key),
                BindingStructures.MapCcsBinding);

        protected override void UpsertCore(CcsPortBinding binding)
        {
            BindingFamilyInterop.ValidateCcsBindingOptions(binding.Options);
            base.UpsertCore(binding);
        }

    }

#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    internal sealed class ScopedCcsBindingOperations : BindingFamilyOperations<ScopedCcsKey, ScopedCcsBinding, HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET>
    {
        public ScopedCcsBindingOperations()
            : base(
                SslBindingKind.ScopedCcs,
                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslScopedCcsCertInfo,
                BindingStructures.CreateSetStruct,
                BindingStructures.CreateDeleteStruct)
        {
        }

        public override bool ProbeSupport()
        {
            HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY query = BindingStructures.CreateNextScopedCcsQuery(0);
            IntPtr queryStructPtr = BindingFamilyInterop.StructureToPtr(query);
            return BindingFamilyInterop.ProbeSupport(
                ConfigId,
                new SafeInteropResult<IntPtr>(queryStructPtr, () => BindingFamilyInterop.FreeStructurePtr<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY>(queryStructPtr)),
                Marshal.SizeOf<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY>());
        }

        protected override IReadOnlyList<ScopedCcsBinding> QueryAllCore() =>
            BindingFamilyInterop.QueryMany<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY, HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET, ScopedCcsBinding>(
                ConfigId,
                BindingStructures.CreateNextScopedCcsQuery,
                BindingStructures.MapScopedCcsBinding);

        protected override ScopedCcsBinding QueryExactCore(ScopedCcsKey key) =>
            BindingFamilyInterop.QuerySingle<HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_QUERY, HttpApi.HTTP_SERVICE_CONFIG_SSL_SNI_SET, ScopedCcsBinding>(
                ConfigId,
                BindingStructures.CreateExactQuery(key),
                BindingStructures.MapScopedCcsBinding);

    }
}
