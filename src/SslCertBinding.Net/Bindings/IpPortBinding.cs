using System;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents an IP-based SSL binding record.
    /// </summary>
    public sealed class IpPortBinding : SslBinding<IpPortKey>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IpPortBinding"/> class.
        /// </summary>
        /// <param name="key">The IP binding key.</param>
        /// <param name="certificateThumbprint">The thumbprint of the bound certificate.</param>
        /// <param name="certificateStoreName">The certificate store name.</param>
        /// <param name="appId">The application identifier.</param>
        /// <param name="options">The binding options.</param>
        public IpPortBinding(IpPortKey key, string certificateThumbprint, string certificateStoreName, Guid appId, BindingOptions options = null)
            : this(key, new(certificateThumbprint, certificateStoreName), appId, options)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="IpPortBinding"/> class.
        /// </summary>
        /// <param name="key">The IP binding key.</param>
        /// <param name="certificate">The bound certificate.</param>
        /// <param name="appId">The application identifier.</param>
        /// <param name="options">The binding options.</param>
        public IpPortBinding(IpPortKey key, SslCertificateReference certificate, Guid appId, BindingOptions options = null)
            : base(appId, options)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        }

        /// <inheritdoc />
        public override IpPortKey Key { get; }

        /// <summary>
        /// Gets the bound certificate.
        /// </summary>
        public SslCertificateReference Certificate { get; }
    }
}
