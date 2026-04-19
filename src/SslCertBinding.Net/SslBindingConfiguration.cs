using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using SslCertBinding.Net.Internal;
using SslCertBinding.Net.Internal.Interop;

namespace SslCertBinding.Net
{
    /// <inheritdoc />
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public class SslBindingConfiguration : ISslBindingConfiguration
    {
        private static readonly HashSet<SslBindingKind> UnsupportedBindingFamilyOverrides = [];
        private static readonly ISslBindingFamilyOperations[] BindingFamilyOperations =
        [
            new IpPortBindingOperations(),
            new HostnamePortBindingOperations(),
            new CcsPortBindingOperations(),
            new ScopedCcsBindingOperations(),
        ];
        private static readonly Dictionary<SslBindingKind, ISslBindingFamilyOperations> BindingFamilyOperationsByKind =
            BindingFamilyOperations.ToDictionary(operations => operations.Kind);
        private static readonly Dictionary<Type, ISslBindingFamilyOperations> BindingFamilyOperationsByKeyType =
            BindingFamilyOperations.ToDictionary(operations => operations.KeyType);
        private static readonly Dictionary<Type, ISslBindingFamilyOperations> BindingFamilyOperationsByBindingType =
            BindingFamilyOperations.ToDictionary(operations => operations.BindingType);
        private readonly Dictionary<SslBindingKind, bool> _bindingFamilySupport = new();

        internal static void OverrideUnsupported(SslBindingKind kind, bool unsupported)
        {
            if (kind == SslBindingKind.IpPort && unsupported)
            {
                throw new ArgumentException("IP-based SSL bindings are always supported and cannot be overridden as unsupported.", nameof(kind));
            }

            if (unsupported)
            {
                UnsupportedBindingFamilyOverrides.Add(kind);
            }
            else
            {
                UnsupportedBindingFamilyOverrides.Remove(kind);
            }
        }

        /// <inheritdoc />
        public IReadOnlyList<ISslBinding> Query()
        {
            var bindings = new List<ISslBinding>();
            foreach (ISslBindingFamilyOperations operations in BindingFamilyOperations)
            {
                if (SupportsBindingFamilyInternal(operations.Kind))
                {
                    bindings.AddRange(operations.QueryAll());
                }
            }

            return bindings;
        }

        /// <inheritdoc />
        public IReadOnlyList<TBinding> Query<TBinding>()
            where TBinding : ISslBinding
        {
            if (typeof(TBinding) == typeof(ISslBinding))
            {
                return Query().Cast<TBinding>().ToArray();
            }

            ISslBindingFamilyOperations operations = GetSupportedBindingOperations<TBinding>();
            return operations.QueryAll().Cast<TBinding>().ToArray();
        }

        /// <inheritdoc />
        public IReadOnlyList<IpPortBinding> Query(IpPortKey key)
        {
            ThrowHelper.ThrowIfNull(key, nameof(key));
            return GetSupportedBindingOperations(key).QueryExact(key).Cast<IpPortBinding>().ToArray();
        }

        /// <inheritdoc />
        public IReadOnlyList<HostnamePortBinding> Query(HostnamePortKey key)
        {
            ThrowHelper.ThrowIfNull(key, nameof(key));
            ISslBindingFamilyOperations operations = GetSupportedBindingOperations(key);
            return operations.QueryExact(key).Cast<HostnamePortBinding>().ToArray();
        }

        /// <inheritdoc />
        public IReadOnlyList<CcsPortBinding> Query(CcsPortKey key)
        {
            ThrowHelper.ThrowIfNull(key, nameof(key));
            ISslBindingFamilyOperations operations = GetSupportedBindingOperations(key);
            return operations.QueryExact(key).Cast<CcsPortBinding>().ToArray();
        }

        /// <inheritdoc />
        public IReadOnlyList<ScopedCcsBinding> Query(ScopedCcsKey key)
        {
            ThrowHelper.ThrowIfNull(key, nameof(key));
            ISslBindingFamilyOperations operations = GetSupportedBindingOperations(key);
            return operations.QueryExact(key).Cast<ScopedCcsBinding>().ToArray();
        }

        /// <inheritdoc />
        public IReadOnlyList<ISslBinding> Query(SslBindingKey key)
        {
            ThrowHelper.ThrowIfNull(key, nameof(key));
            ISslBindingFamilyOperations operations = GetSupportedBindingOperations(key);
            return operations.QueryExact(key);
        }

        /// <inheritdoc />
        public void Upsert(ISslBinding binding)
        {
            ThrowHelper.ThrowIfNull(binding, nameof(binding));
            ISslBindingFamilyOperations operations = GetSupportedBindingOperations(binding);
            operations.Upsert(binding);
        }

        /// <inheritdoc />
        public void Delete(SslBindingKey key)
        {
            ThrowHelper.ThrowIfNull(key, nameof(key));

            Delete(new[] { key });
        }

        /// <inheritdoc />
        public void Delete(IReadOnlyCollection<SslBindingKey> keys)
        {
            _ = keys ?? throw new ArgumentNullException(nameof(keys));
            if (keys.Count == 0)
            {
                return;
            }

            ValidateKeys(keys);

            HttpApi.CallHttpApi(
                delegate
                {
                    foreach (SslBindingKey key in keys)
                    {
                        DeleteInternal(key);
                    }
                });
        }

        internal bool SupportsBindingFamilyInternal(SslBindingKind kind)
        {
            if (HasUnsupportedBindingFamilyOverride(kind))
            {
                return false;
            }

            if (_bindingFamilySupport.TryGetValue(kind, out bool supported))
            {
                return supported;
            }

            supported = GetBindingOperations(kind).ProbeSupport();
            _bindingFamilySupport[kind] = supported;
            return supported;
        }

        internal void EnsureBindingFamilySupportedInternal(SslBindingKind kind)
        {
            if (!SupportsBindingFamilyInternal(kind))
            {
                throw CreateBindingFamilyPlatformNotSupportedException(kind);
            }
        }

        private void DeleteInternal(SslBindingKey key)
        {
            ThrowHelper.ThrowIfNull(key, nameof(key));
            ISslBindingFamilyOperations operations = GetSupportedBindingOperations(key);
            operations.Delete(key);
        }

        private void EnsureBindingFamilySupportedIfNeeded(SslBindingKind kind)
        {
            EnsureBindingFamilySupportedInternal(kind);
        }

        private ISslBindingFamilyOperations GetSupportedBindingOperations<TBinding>()
            where TBinding : ISslBinding
        {
            ISslBindingFamilyOperations operations = GetBindingOperations<TBinding>();
            EnsureBindingFamilySupportedIfNeeded(operations.Kind);
            return operations;
        }

        private ISslBindingFamilyOperations GetSupportedBindingOperations(SslBindingKey key)
        {
            ISslBindingFamilyOperations operations = GetBindingOperations(key);
            EnsureBindingFamilySupportedIfNeeded(operations.Kind);
            return operations;
        }

        private ISslBindingFamilyOperations GetSupportedBindingOperations(ISslBinding binding)
        {
            ISslBindingFamilyOperations operations = GetBindingOperations(binding);
            EnsureBindingFamilySupportedIfNeeded(operations.Kind);
            return operations;
        }

        private void ValidateKeys(IReadOnlyCollection<SslBindingKey> keys)
        {
            var operationsSet = new HashSet<ISslBindingFamilyOperations>();

            foreach (SslBindingKey key in keys)
            {
                if (key == null)
                {
                    throw new ArgumentException("The collection cannot contain null items.", nameof(keys));
                }

                operationsSet.Add(GetBindingOperations(key));
            }

            foreach (ISslBindingFamilyOperations operations in operationsSet)
            {
                EnsureBindingFamilySupportedInternal(operations.Kind);
            }
        }

        private static bool HasUnsupportedBindingFamilyOverride(SslBindingKind kind)
        {
            return UnsupportedBindingFamilyOverrides.Contains(kind);
        }

        private static NotSupportedException CreateNotSupportedException(Type type)
        {
            return new NotSupportedException(
                string.Format(
                    CultureInfo.InvariantCulture,
                    "The binding type '{0}' is not supported by this configuration.",
                    type.FullName));
        }

        private static PlatformNotSupportedException CreateBindingFamilyPlatformNotSupportedException(SslBindingKind kind) =>
            kind switch
            {
                SslBindingKind.HostnamePort => new("Hostname-based SSL bindings (SNI) are not supported on this version of Windows."),
                SslBindingKind.CcsPort => new("Central certificate store SSL bindings (CCS) are not supported on this version of Windows."),
                SslBindingKind.ScopedCcs => new("Scoped central certificate store SSL bindings are not supported on this version of Windows."),
                _ => new("The requested SSL binding family is not supported on this version of Windows."),
            };

        private static ISslBindingFamilyOperations GetBindingOperations(SslBindingKind kind)
        {
            if (BindingFamilyOperationsByKind.TryGetValue(kind, out ISslBindingFamilyOperations operations))
            {
                return operations;
            }

            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        private static ISslBindingFamilyOperations GetBindingOperations(SslBindingKey key) =>
            BindingFamilyOperationsByKeyType.TryGetValue(key.GetType(), out ISslBindingFamilyOperations operations)
                ? operations
                : throw CreateNotSupportedException(key.GetType());

        private static ISslBindingFamilyOperations GetBindingOperations<TBinding>()
            where TBinding : ISslBinding =>
            GetBindingOperationsForBindingType(typeof(TBinding));

        private static ISslBindingFamilyOperations GetBindingOperationsForBindingType(Type type)
        {
            if (BindingFamilyOperationsByBindingType.TryGetValue(type, out ISslBindingFamilyOperations operations))
            {
                return operations;
            }

            throw CreateNotSupportedException(type);
        }

        private static ISslBindingFamilyOperations GetBindingOperations(ISslBinding binding) =>
            GetBindingOperationsForBindingType(binding.GetType());
    }
}
