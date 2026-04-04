using System;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents additional options for binding an SSL certificate.
    /// </summary>
    public class BindingOptions
    {
        /// <summary>
        /// The time interval after which to check for an updated certificate revocation list (CRL).
        /// If this value is zero, the new CRL is updated only when the previous one expires.
        /// </summary>
        public TimeSpan RevocationFreshnessTime { get; set; }

        /// <summary>
        /// The timeout interval for an attempt to retrieve a certificate revocation list from the remote URL.
        /// </summary>
        public TimeSpan RevocationUrlRetrievalTimeout { get; set; }

        /// <summary>
        /// The SSL control identifier, which specifies the list of the certificate issuers that can be trusted.
        /// This list can be a subset of the certificate issuers that are trusted by the computer.
        /// </summary>
        public string SslCtlIdentifier { get; set; }

        /// <summary>
        /// The name of the store under the Local Machine store location where the control identifier pointed to by <see cref="SslCtlIdentifier"/> is stored.
        /// </summary>
        public string SslCtlStoreName { get; set; }

        /// <summary>
        /// Indicates whether client certificates are mapped where possible to corresponding operating-system user accounts based on the certificate mapping rules stored in Active Directory.
        /// </summary>
        public bool UseDsMappers { get; set; }

        /// <summary>
        /// Indicates whether a client certificate is enabled to be cached locally for subsequent use.
        /// </summary>
        public bool NegotiateCertificate { get; set; }

        /// <summary>
        /// Prevents SSL requests from being passed to low-level ISAPI filters.
        /// </summary>
        public bool DoNotPassRequestsToRawFilters { get; set; }

        /// <summary>
        /// Indicates that the client certificate is not to be verified for revocation.
        /// </summary>
        public bool DoNotVerifyCertificateRevocation { get; set; }

        /// <summary>
        /// Indicates that only cached certificates are to be used for the revocation check.
        /// </summary>
        public bool VerifyRevocationWithCachedCertificateOnly { get; set; }

        /// <summary>
        /// Indicates that the <see cref="RevocationFreshnessTime"/> setting is enabled.
        /// </summary>
        public bool EnableRevocationFreshnessTime { get; set; }

        /// <summary>
        /// Indicates that no usage check is to be performed.
        /// </summary>
        public bool NoUsageCheck { get; set; }

        /// <summary>
        /// Disables version 1.2 of the TLS protocol.
        /// </summary>
        public bool DisableTls12 { get; set; }
    }
}
