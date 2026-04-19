using System;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents a hostname-based SSL binding record.
    /// </summary>
    public sealed class HostnamePortBinding : SslBinding<HostnamePortKey>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HostnamePortBinding"/> class.
        /// </summary>
        /// <param name="key">The hostname binding key.</param>
        /// <param name="certificateThumbprint">The thumbprint of the bound certificate.</param>
        /// <param name="certificateStoreName">The certificate store name.</param>
        /// <param name="appId">The application identifier.</param>
        /// <param name="options">The binding options.</param>
        public HostnamePortBinding(HostnamePortKey key, string certificateThumbprint, string certificateStoreName, Guid appId, BindingOptions options = null)
            : this(key, new(certificateThumbprint, certificateStoreName), appId, options)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HostnamePortBinding"/> class.
        /// </summary>
        /// <param name="key">The hostname binding key.</param>
        /// <param name="certificate">The bound certificate.</param>
        /// <param name="appId">The application identifier.</param>
        /// <param name="options">The binding options.</param>
        public HostnamePortBinding(HostnamePortKey key, SslCertificateReference certificate, Guid appId, BindingOptions options = null)
            : base(appId, options)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        }

        /// <inheritdoc />
        public override HostnamePortKey Key { get; }

        /// <summary>
        /// Gets the bound certificate.
        /// </summary>
        public SslCertificateReference Certificate { get; }
    }
}
