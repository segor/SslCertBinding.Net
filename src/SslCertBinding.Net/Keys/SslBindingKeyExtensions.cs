using System;
using System.Net;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Convenience conversions from platform endpoints to SSL binding keys.
    /// </summary>
    public static class SslBindingKeyExtensions
    {
        /// <summary>
        /// Creates an <see cref="IpPortKey"/> from an <see cref="IPEndPoint"/>.
        /// </summary>
        /// <param name="endPoint">The endpoint to convert.</param>
        /// <returns>
        /// The converted key, or <c>null</c> when <paramref name="endPoint"/> is <c>null</c>.
        /// </returns>
        public static IpPortKey? ToSslBindingKey(this IPEndPoint? endPoint) =>
            endPoint == null ? null : new IpPortKey(endPoint);

        /// <summary>
        /// Creates a <see cref="HostnamePortKey"/> from a <see cref="DnsEndPoint"/>.
        /// </summary>
        /// <param name="endPoint">The endpoint to convert.</param>
        /// <returns>
        /// The converted key, or <c>null</c> when <paramref name="endPoint"/> is <c>null</c>.
        /// </returns>
        public static HostnamePortKey? ToHostnamePortKey(this DnsEndPoint? endPoint) =>
            endPoint == null ? null : new HostnamePortKey(endPoint);

        /// <summary>
        /// Creates a <see cref="ScopedCcsKey"/> from a <see cref="DnsEndPoint"/>.
        /// </summary>
        /// <param name="endPoint">The endpoint to convert.</param>
        /// <returns>
        /// The converted key, or <c>null</c> when <paramref name="endPoint"/> is <c>null</c>.
        /// </returns>
        public static ScopedCcsKey? ToScopedCcsKey(this DnsEndPoint? endPoint) =>
            endPoint == null ? null : new ScopedCcsKey(endPoint);
    }
}
