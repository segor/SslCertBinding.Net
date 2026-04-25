using System;
using System.Diagnostics.CodeAnalysis;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents a binding-family-specific SSL binding key.
    /// </summary>
    public abstract class SslBindingKey
    {
        /// <summary>
        /// Gets the binding family represented by this key.
        /// </summary>
        public abstract SslBindingKind Kind { get; }

        /// <summary>
        /// Parses a binding key using an explicit binding family.
        /// </summary>
        /// <param name="value">The textual representation of the key.</param>
        /// <param name="kind">The binding family to parse.</param>
        /// <returns>The parsed binding key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <c>null</c>.</exception>
        /// <exception cref="FormatException">Thrown when <paramref name="value"/> is not valid for the specified binding family.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="kind"/> is not a supported binding family.</exception>
        public static SslBindingKey Parse(string value, SslBindingKind kind)
        {
            switch (kind)
            {
                case SslBindingKind.IpPort:
                    return IpPortKey.Parse(value);
                case SslBindingKind.HostnamePort:
                    return HostnamePortKey.Parse(value);
                case SslBindingKind.CcsPort:
                    return CcsPortKey.Parse(value);
                case SslBindingKind.ScopedCcs:
                    return ScopedCcsKey.Parse(value);
                default:
                    throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        /// <summary>
        /// Tries to parse a binding key using an explicit binding family.
        /// </summary>
        /// <param name="value">The textual representation of the key.</param>
        /// <param name="kind">The binding family to parse.</param>
        /// <param name="key">When this method returns, contains the parsed key if parsing succeeded.</param>
        /// <returns><c>true</c> if parsing succeeded; otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="kind"/> is not a supported binding family.</exception>
        public static bool TryParse(string? value, SslBindingKind kind, [NotNullWhen(true)] out SslBindingKey? key)
        {
            switch (kind)
            {
                case SslBindingKind.IpPort:
                    if (IpPortKey.TryParse(value, out IpPortKey? ipKey))
                    {
                        key = ipKey;
                        return true;
                    }

                    break;
                case SslBindingKind.HostnamePort:
                    if (HostnamePortKey.TryParse(value, out HostnamePortKey? hostnameKey))
                    {
                        key = hostnameKey;
                        return true;
                    }

                    break;
                case SslBindingKind.CcsPort:
                    if (CcsPortKey.TryParse(value, out CcsPortKey? ccsKey))
                    {
                        key = ccsKey;
                        return true;
                    }

                    break;
                case SslBindingKind.ScopedCcs:
                    if (ScopedCcsKey.TryParse(value, out ScopedCcsKey? scopedCcsKey))
                    {
                        key = scopedCcsKey;
                        return true;
                    }

                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(kind));
            }

            key = null;
            return false;
        }
    }
}
