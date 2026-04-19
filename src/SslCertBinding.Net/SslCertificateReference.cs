using System;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents the certificate material used by a direct-certificate SSL binding.
    /// </summary>
    public sealed class SslCertificateReference
    {
        /// <inheritdoc cref="SslCertificateReference.SslCertificateReference(string, string)" />
        public SslCertificateReference(string thumbprint, StoreName storeName)
            : this(thumbprint, storeName.ToString())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SslCertificateReference"/> class.
        /// </summary>
        /// <param name="thumbprint">The certificate thumbprint.</param>
        /// <param name="storeName">The certificate store name.</param>
        /// <exception cref="ArgumentException">Thrown when <paramref name="thumbprint"/> is null or empty.</exception>
        public SslCertificateReference(string thumbprint, string storeName)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException("Value cannot be null or empty.", nameof(thumbprint));
            }

            Thumbprint = thumbprint;
            StoreName = storeName ?? "MY";
        }

        /// <inheritdoc cref="SslCertificateReference.From(System.Security.Cryptography.X509Certificates.X509Certificate2, string)" />
        public static SslCertificateReference From(X509Certificate2 certificate, StoreName storeName) =>
            new SslCertificateReference(
                (certificate ?? throw new ArgumentNullException(nameof(certificate))).Thumbprint,
                storeName);

        /// <summary>
        /// Creates a certificate reference from an <see cref="X509Certificate2"/>
        /// and an explicit Windows certificate store.
        /// </summary>
        /// <param name="certificate">The certificate whose thumbprint should be referenced.</param>
        /// <param name="storeName">The certificate store name.</param>
        /// <returns>The certificate reference.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is <c>null</c>.</exception>
        public static SslCertificateReference From(X509Certificate2 certificate, string storeName) =>
            new SslCertificateReference(
                (certificate ?? throw new ArgumentNullException(nameof(certificate))).Thumbprint,
                storeName);

        /// <summary>
        /// Gets the certificate thumbprint.
        /// </summary>
        public string Thumbprint { get; }

        /// <summary>
        /// Gets the certificate store name.
        /// </summary>
        public string StoreName { get; }
    }
}
