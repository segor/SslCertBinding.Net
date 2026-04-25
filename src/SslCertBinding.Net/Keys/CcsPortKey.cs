using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using SslCertBinding.Net.Internal;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents the key for a central certificate store SSL binding.
    /// </summary>
    public sealed class CcsPortKey : SslBindingKey, IEquatable<CcsPortKey>
    {
        private const string FormatErrorMessage = "Invalid CCS binding key format.";

        /// <summary>
        /// Initializes a new instance of the <see cref="CcsPortKey"/> class.
        /// </summary>
        /// <param name="port">The bound port.</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="port"/> is not a valid TCP port.</exception>
        public CcsPortKey(int port)
        {
            if (!BindingKeyParser.IsValidPort(port))
            {
                throw new ArgumentOutOfRangeException(nameof(port));
            }

            Port = port;
        }

        /// <inheritdoc />
        public override SslBindingKind Kind => SslBindingKind.CcsPort;

        /// <summary>
        /// Gets the bound port.
        /// </summary>
        public int Port { get; }

        /// <summary>
        /// Creates a binding key from a TCP port.
        /// </summary>
        /// <param name="port">The port to convert.</param>
        /// <returns>The converted key.</returns>
        public static CcsPortKey From(int port) => new(port);

        /// <summary>
        /// Tries to parse a CCS binding key.
        /// </summary>
        /// <param name="value">The textual representation of the key.</param>
        /// <param name="key">When this method returns, contains the parsed key if parsing succeeded.</param>
        /// <returns><c>true</c> if parsing succeeded; otherwise <c>false</c>.</returns>
        public static bool TryParse(string? value, [NotNullWhen(true)] out CcsPortKey? key)
        {
            key = null;
            if (!BindingKeyParser.TryParsePort(value, out int port))
            {
                return false;
            }

            key = new(port);
            return true;
        }

        /// <summary>
        /// Parses a CCS binding key.
        /// </summary>
        /// <param name="value">The textual representation of the key.</param>
        /// <returns>The parsed key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <c>null</c>.</exception>
        /// <exception cref="FormatException">Thrown when <paramref name="value"/> is not a valid CCS binding key.</exception>
        public static CcsPortKey Parse(string value)
        {
            if (!TryParse(value ?? throw new ArgumentNullException(nameof(value)), out CcsPortKey? key))
            {
                throw new FormatException(FormatErrorMessage);
            }

            return key;
        }

        /// <inheritdoc />
        public override string ToString() => Port.ToString(CultureInfo.InvariantCulture);

        /// <inheritdoc />
        public override bool Equals(object? obj) => obj is CcsPortKey key && Equals(key);

        /// <inheritdoc />
        public override int GetHashCode() => Port.GetHashCode();

        /// <inheritdoc />
        public bool Equals(CcsPortKey? other) => other != null && Port == other.Port;
    }
}
