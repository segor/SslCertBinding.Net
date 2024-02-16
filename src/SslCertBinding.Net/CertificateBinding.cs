using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents a record with binding of an SSL certificate to an IP endpoint in the SSL configuration store.
    /// </summary>
    public class CertificateBinding
    {
        /// <summary>
        /// Gets the thumbprint of the SSL certificate.
        /// </summary>
        public string Thumbprint { get; private set; }

        /// <summary>
        /// Gets the name of the certificate store from which the server certificate is to be read.
        /// If set to <c>null</c>, "MY" is assumed as the default name. The specified certificate store name must be present in the Local Machine store location.
        /// </summary>
        public string StoreName { get; private set; }

        /// <summary>
        /// Gets the endpoint with which this SSL certificate is associated.
        /// If the <see cref="IPEndPoint.Address"/> property is set to 0.0.0.0, the certificate is applicable to all IPv4 and IPv6 addresses.
        /// If the <see cref="IPEndPoint.Address"/> property is set to [::], the certificate is applicable to all IPv6 addresses.
        /// </summary>
        public BindingEndPoint EndPoint { get; private set; }

        /// <summary>
        /// Gets the unique identifier of the application setting this record.
        /// </summary>
        public Guid AppId { get; private set; }

        /// <summary>
        /// Gets additional options for the binding.
        /// </summary>
        public BindingOptions Options { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateBinding"/> class.
        /// </summary>
        /// <param name="certificateThumbprint">The thumbprint of the SSL certificate.</param>
        /// <param name="certificateStoreName">The name of the certificate store.</param>
        /// <param name="endPoint">The endpoint.</param>
        /// <param name="appId">The application ID.</param>
        /// <param name="options">Additional binding options.</param>
        /// <exception cref="ArgumentException">Thrown when <paramref name="certificateThumbprint"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipPort"/> is null.</exception>
        public CertificateBinding(string certificateThumbprint, StoreName certificateStoreName, DnsEndPoint endPoint, Guid appId, BindingOptions options = default)
            : this(certificateThumbprint, certificateStoreName.ToString(), endPoint, appId, options) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateBinding"/> class.
        /// </summary>
        /// <param name="certificateThumbprint">The thumbprint of the SSL certificate.</param>
        /// <param name="certificateStoreName">The name of the certificate store.</param>
        /// <param name="endPoint">The IP endpoint.</param>
        /// <param name="appId">The application ID.</param>
        /// <param name="options">Additional binding options.</param>
        /// <exception cref="ArgumentException">Thrown when <paramref name="certificateThumbprint"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipPort"/> is null.</exception>
        public CertificateBinding(string certificateThumbprint, string certificateStoreName, DnsEndPoint endPoint, Guid appId, BindingOptions options = default)
        {
            if (string.IsNullOrEmpty(certificateThumbprint))
            {
                throw new ArgumentException($"Value cannot be null or empty.", nameof(certificateThumbprint));
            }

            Thumbprint = certificateThumbprint;
            StoreName = certificateStoreName ?? "MY"; // StoreName of null is assumed to be My / Personal. See https://msdn.microsoft.com/en-us/library/windows/desktop/aa364647(v=vs.85).aspx
            EndPoint = endPoint.ToBindingEndPoint();
            AppId = appId;
            Options = options ?? new BindingOptions();
        }
    }
}
