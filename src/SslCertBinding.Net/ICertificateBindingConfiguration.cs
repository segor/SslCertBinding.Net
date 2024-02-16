using System.Collections.Generic;
using System.Net;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Provides methods to manage SSL certificate bindings.
    /// </summary>
    public interface ICertificateBindingConfiguration
    {
        /// <summary>
        /// Queries the SSL certificate bindings for the specified endpoint.
        /// </summary>
        /// <param name="endPoint">The IP endpoint to query. If <c>null</c>, all bindings are returned.</param>
        /// <returns>A list of <see cref="CertificateBinding"/> objects.</returns>
        IReadOnlyList<CertificateBinding> Query(DnsEndPoint endPoint = null);

        /// <summary>
        /// Binds an SSL certificate to an endpoint.
        /// </summary>
        /// <param name="binding">The <see cref="CertificateBinding"/> object containing the binding information.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="binding"/> is null.</exception>
        /// <exception cref="Win32Exception">Thrown when an Win32 error occurred.</exception>
        void Bind(CertificateBinding binding);

        /// <summary>
        /// Deletes an SSL certificate binding for the specified endpoint.
        /// </summary>
        /// <param name="endPoint">The endpoint to delete the binding for.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="endPoint"/> is null.</exception>
        /// <exception cref="Win32Exception">Thrown when an Win32 error occurred.</exception>
        void Delete(DnsEndPoint endPoint);

        /// <summary>
        /// Deletes SSL certificate bindings for the specified endpoints.
        /// </summary>
        /// <param name="endPoints">The collection of endpoints to delete the bindings for.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="endPoints"/> is null.</exception>
        /// <exception cref="Win32Exception">Thrown when an Win32 error occurred.</exception>
        void Delete(IReadOnlyCollection<DnsEndPoint> endPoints);
    }
}