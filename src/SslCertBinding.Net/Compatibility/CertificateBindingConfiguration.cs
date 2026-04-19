#pragma warning disable CS0618
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using SslCertBinding.Net.Internal;

namespace SslCertBinding.Net
{
    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    [Obsolete("Use SslBindingConfiguration with IpPortBinding and IpPortKey instead.")]
    public class CertificateBindingConfiguration : ICertificateBindingConfiguration
    {
        private readonly ISslBindingConfiguration _configuration;

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateBindingConfiguration"/> class.
        /// </summary>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform.</exception>
        public CertificateBindingConfiguration()
            : this(new SslBindingConfiguration())
        {
        }

        internal CertificateBindingConfiguration(ISslBindingConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        /// <inheritdoc />
        public IReadOnlyList<CertificateBinding> Query(IPEndPoint ipPort = null)
        {
            IReadOnlyList<IpPortBinding> bindings = ipPort == null
                ? _configuration.Query<IpPortBinding>()
                : _configuration.Query(new IpPortKey(ipPort));

            return [.. bindings.Select(CertificateBinding.From)];
        }

        /// <inheritdoc />
        public void Bind(CertificateBinding binding)
        {
            ThrowHelper.ThrowIfNull(binding, nameof(binding));

            _configuration.Upsert(binding.ToIpPortBinding());
        }

        /// <inheritdoc />
        public void Delete(IPEndPoint endPoint)
        {
            ThrowHelper.ThrowIfNull(endPoint, nameof(endPoint));

            _configuration.Delete(new IpPortKey(endPoint));
        }

        /// <inheritdoc />
        public void Delete(IReadOnlyCollection<IPEndPoint> endPoints)
        {
            _ = endPoints ?? throw new ArgumentNullException(nameof(endPoints));
            if (endPoints.Count == 0)
            {
                return;
            }

            var keys = new SslBindingKey[endPoints.Count];
            int index = 0;
            foreach (IPEndPoint endPoint in endPoints)
            {
                if (endPoint == null)
                {
                    throw new ArgumentException("The collection cannot contain null items.", nameof(endPoints));
                }

                keys[index++] = new IpPortKey(endPoint);
            }

            _configuration.Delete(keys);
        }
    }
}
#pragma warning restore CS0618
