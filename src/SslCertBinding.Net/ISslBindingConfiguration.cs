using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Provides methods to manage SSL bindings across supported binding families.
    /// </summary>
    public interface ISslBindingConfiguration
    {
        /// <summary>
        /// Queries all supported SSL bindings.
        /// </summary>
        /// <returns>The matching bindings.</returns>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform.</exception>
        /// <exception cref="Win32Exception">Thrown when the underlying HTTP Server API query fails.</exception>
        IReadOnlyList<ISslBinding> Query();

        /// <summary>
        /// Queries all bindings of the specified concrete binding type.
        /// </summary>
        /// <typeparam name="TBinding">The binding family to enumerate.</typeparam>
        /// <returns>The matching bindings.</returns>
        /// <exception cref="NotSupportedException">Thrown when <typeparamref name="TBinding"/> is not a supported binding type.</exception>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform or when the requested binding family is not supported on the current Windows version.</exception>
        /// <exception cref="Win32Exception">Thrown when the underlying HTTP Server API query fails.</exception>
        IReadOnlyList<TBinding> Query<TBinding>() where TBinding : ISslBinding;

        /// <summary>
        /// Queries an exact IP-based SSL binding.
        /// </summary>
        /// <param name="key">The IP binding key to query.</param>
        /// <returns>The matching IP bindings.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <c>null</c>.</exception>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform.</exception>
        /// <exception cref="Win32Exception">Thrown when the underlying HTTP Server API query fails.</exception>
        IReadOnlyList<IpPortBinding> Query(IpPortKey key);

        /// <summary>
        /// Queries an exact hostname-based SSL binding.
        /// </summary>
        /// <param name="key">The hostname binding key to query.</param>
        /// <returns>The matching hostname bindings.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <c>null</c>.</exception>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform or when the current Windows version does not support hostname bindings (SNI).</exception>
        /// <exception cref="Win32Exception">Thrown when the underlying HTTP Server API query fails.</exception>
        IReadOnlyList<HostnamePortBinding> Query(HostnamePortKey key);

        /// <summary>
        /// Queries an exact SSL binding using a runtime-selected binding key.
        /// </summary>
        /// <param name="key">The binding key to query.</param>
        /// <returns>The matching bindings.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <c>null</c>.</exception>
        /// <exception cref="NotSupportedException">Thrown when <paramref name="key"/> is not a supported binding key type.</exception>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform or when the selected binding family is not supported on the current Windows version.</exception>
        /// <exception cref="Win32Exception">Thrown when the underlying HTTP Server API query fails.</exception>
        IReadOnlyList<ISslBinding> Query(SslBindingKey key);

        /// <summary>
        /// Adds or updates an SSL binding.
        /// </summary>
        /// <param name="binding">The binding to apply.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="binding"/> is <c>null</c>.</exception>
        /// <exception cref="NotSupportedException">Thrown when <paramref name="binding"/> is not a supported binding type.</exception>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform or when the selected binding family is not supported on the current Windows version.</exception>
        /// <exception cref="Win32Exception">Thrown when the underlying HTTP Server API operation fails.</exception>
        void Upsert(ISslBinding binding);

        /// <summary>
        /// Deletes an SSL binding.
        /// </summary>
        /// <param name="key">The binding key to delete.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <c>null</c>.</exception>
        /// <exception cref="NotSupportedException">Thrown when <paramref name="key"/> is not a supported binding key type.</exception>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform or when the selected binding family is not supported on the current Windows version.</exception>
        /// <exception cref="Win32Exception">Thrown when the underlying HTTP Server API operation fails.</exception>
        void Delete(SslBindingKey key);

        /// <summary>
        /// Deletes SSL bindings.
        /// </summary>
        /// <param name="keys">The binding keys to delete.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="keys"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="keys"/> contains a <c>null</c> item.</exception>
        /// <exception cref="NotSupportedException">Thrown when <paramref name="keys"/> contains an unsupported binding key type.</exception>
        /// <exception cref="PlatformNotSupportedException">Thrown when the Windows HTTP Server API is unavailable on the current platform or when any selected binding family is not supported on the current Windows version.</exception>
        /// <exception cref="Win32Exception">Thrown when the underlying HTTP Server API operation fails.</exception>
        void Delete(IReadOnlyCollection<SslBindingKey> keys);
    }
}
