#pragma warning disable CS0618
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Legacy IP-only wrapper over the new binding-family API.
    /// This interface remains available as a soft migration path for existing callers,
    /// but it intentionally exposes only <c>ipport</c> bindings and never returns hostname/SNI bindings.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    [Obsolete("Use ISslBindingConfiguration and SslBindingConfiguration instead.")]
    public interface ICertificateBindingConfiguration
    {
        /// <summary>
        /// Queries the SSL certificate bindings for the specified IP endpoint.
        /// </summary>
        /// <param name="ipPort">The IP endpoint to query. If <c>null</c>, all IP-based bindings are returned. Hostname/SNI bindings are never returned by this legacy API.</param>
        /// <returns>A list of <see cref="CertificateBinding"/> objects.</returns>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform.</exception>
        /// <exception cref="System.ComponentModel.Win32Exception">Thrown when the underlying HTTP Server API query fails.</exception>
        IReadOnlyList<CertificateBinding> Query(IPEndPoint? ipPort = null);

        /// <summary>
        /// Adds or updates an SSL certificate binding.
        /// </summary>
        /// <param name="binding">The binding to apply.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="binding"/> is <c>null</c>.</exception>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform.</exception>
        /// <exception cref="System.ComponentModel.Win32Exception">Thrown when the underlying HTTP Server API operation fails.</exception>
        void Bind(CertificateBinding binding);

        /// <summary>
        /// Deletes an SSL certificate binding for the specified IP endpoint.
        /// </summary>
        /// <param name="endPoint">The IP endpoint to delete the binding for.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="endPoint"/> is <c>null</c>.</exception>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform.</exception>
        /// <exception cref="System.ComponentModel.Win32Exception">Thrown when the underlying HTTP Server API operation fails.</exception>
        void Delete(IPEndPoint endPoint);

        /// <summary>
        /// Deletes SSL certificate bindings for the specified IP endpoints.
        /// </summary>
        /// <param name="endPoints">The endpoints to delete.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="endPoints"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="endPoints"/> contains a <c>null</c> item.</exception>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform.</exception>
        /// <exception cref="System.ComponentModel.Win32Exception">Thrown when the underlying HTTP Server API operation fails.</exception>
        void Delete(IReadOnlyCollection<IPEndPoint> endPoints);
    }
}
#pragma warning restore CS0618
