#pragma warning disable CS0618
using System;
using System.ComponentModel;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using SslCertBinding.Net.Internal;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Legacy IP-only wrapper over the new binding-family API.
    /// This type remains available as a soft migration path for existing callers,
    /// but it intentionally models only <c>ipport</c> bindings and does not represent hostname/SNI bindings.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    [Obsolete("Use SslBindingConfiguration with IpPortBinding, IpPortKey, and SslCertificateReference instead.")]
    public class CertificateBinding
    {
        /// <inheritdoc cref="CertificateBinding.CertificateBinding(string, string, System.Net.IPEndPoint, System.Guid, BindingOptions)" />
        public CertificateBinding(string certificateThumbprint, StoreName certificateStoreName, IPEndPoint ipPort, Guid appId, BindingOptions options = null)
            : this(certificateThumbprint, certificateStoreName.ToString(), ipPort, appId, options)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateBinding"/> class.
        /// </summary>
        /// <param name="certificateThumbprint">The thumbprint of the SSL certificate.</param>
        /// <param name="certificateStoreName">The name of the certificate store.</param>
        /// <param name="ipPort">The IP endpoint.</param>
        /// <param name="appId">The application ID.</param>
        /// <param name="options">Additional binding options.</param>
        /// <exception cref="ArgumentException">Thrown when <paramref name="certificateThumbprint"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipPort"/> is <c>null</c>.</exception>
        public CertificateBinding(string certificateThumbprint, string certificateStoreName, IPEndPoint ipPort, Guid appId, BindingOptions options = null)
        {
            if (string.IsNullOrEmpty(certificateThumbprint))
            {
                throw new ArgumentException("Value cannot be null or empty.", nameof(certificateThumbprint));
            }

            Thumbprint = certificateThumbprint;
            StoreName = certificateStoreName ?? "MY";
            IpPort = ipPort ?? throw new ArgumentNullException(nameof(ipPort));
            AppId = appId;
            Options = CloneOptions(options);
        }

        /// <summary>
        /// Gets the thumbprint of the SSL certificate.
        /// </summary>
        public string Thumbprint { get; }

        /// <summary>
        /// Gets the certificate store name.
        /// </summary>
        public string StoreName { get; }

        /// <summary>
        /// Gets the IP endpoint with which this SSL certificate is associated.
        /// This legacy type always represents an <c>ipport</c> binding.
        /// </summary>
        public IPEndPoint IpPort { get; }

        /// <summary>
        /// Gets the unique identifier of the application setting this record.
        /// </summary>
        public Guid AppId { get; }

        /// <summary>
        /// Gets additional options for the binding.
        /// </summary>
        public BindingOptions Options { get; }

        internal static CertificateBinding From(IpPortBinding binding)
        {
            ThrowHelper.ThrowIfNull(binding, nameof(binding));

            return new(
                binding.Certificate.Thumbprint,
                binding.Certificate.StoreName,
                binding.Key.ToIPEndPoint(),
                binding.AppId,
                binding.Options);
        }

        internal IpPortBinding ToIpPortBinding()
        {
            return new(
                new(IpPort),
                new(Thumbprint, StoreName),
                AppId,
                CloneOptions(Options));
        }

        internal static BindingOptions CloneOptions(BindingOptions options) =>
            options == null
                ? new()
                : new()
            {
                RevocationFreshnessTime = options.RevocationFreshnessTime,
                RevocationUrlRetrievalTimeout = options.RevocationUrlRetrievalTimeout,
                SslCtlIdentifier = options.SslCtlIdentifier,
                SslCtlStoreName = options.SslCtlStoreName,
                UseDsMappers = options.UseDsMappers,
                NegotiateCertificate = options.NegotiateCertificate,
                DoNotPassRequestsToRawFilters = options.DoNotPassRequestsToRawFilters,
                DoNotVerifyCertificateRevocation = options.DoNotVerifyCertificateRevocation,
                VerifyRevocationWithCachedCertificateOnly = options.VerifyRevocationWithCachedCertificateOnly,
                EnableRevocationFreshnessTime = options.EnableRevocationFreshnessTime,
                NoUsageCheck = options.NoUsageCheck,
                DisableTls12 = options.DisableTls12,
            };
    }
}
#pragma warning restore CS0618
