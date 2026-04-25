using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using SslCertBinding.Net.Internal;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents the key for a hostname-based SSL binding.
    /// </summary>
    public sealed class HostnamePortKey : SslBindingKey, IEquatable<HostnamePortKey>, IEquatable<DnsEndPoint>
    {
        private const string FormatErrorMessage = "Invalid hostname binding key format.";

        /// <summary>
        /// Initializes a new instance of the <see cref="HostnamePortKey"/> class.
        /// </summary>
        /// <param name="hostname">The bound hostname.</param>
        /// <param name="port">The bound port.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="hostname"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="hostname"/> is empty, whitespace, or not a valid DNS hostname.</exception>
        public HostnamePortKey(string hostname, int port)
            : this(new DnsEndPoint(hostname ?? throw new ArgumentNullException(nameof(hostname)), port))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HostnamePortKey"/> class.
        /// </summary>
        /// <param name="endPoint">The endpoint to convert.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="endPoint"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="endPoint"/> does not contain a valid DNS hostname.</exception>
        public HostnamePortKey(DnsEndPoint endPoint)
        {
            ThrowHelper.ThrowIfNull(endPoint, nameof(endPoint));

            Hostname = BindingKeyParser.RequireValidHostname(endPoint.Host, nameof(endPoint));
            Port = endPoint.Port;
        }

        /// <inheritdoc />
        public override SslBindingKind Kind => SslBindingKind.HostnamePort;

        /// <summary>
        /// Gets the bound hostname.
        /// </summary>
        public string Hostname { get; }

        /// <summary>
        /// Gets the bound port.
        /// </summary>
        public int Port { get; }

        /// <summary>
        /// Creates a <see cref="DnsEndPoint"/> from this key.
        /// </summary>
        /// <returns>The corresponding endpoint.</returns>
        public DnsEndPoint ToDnsEndPoint() => new(Hostname, Port);

        /// <summary>
        /// Creates a binding key from a <see cref="DnsEndPoint"/>.
        /// </summary>
        /// <param name="endPoint">The endpoint to convert.</param>
        /// <returns>The converted key.</returns>
        public static HostnamePortKey From(DnsEndPoint endPoint) => new(endPoint);

        /// <summary>
        /// Tries to parse a hostname binding key.
        /// </summary>
        /// <param name="value">The textual representation of the key.</param>
        /// <param name="key">When this method returns, contains the parsed key if parsing succeeded.</param>
        /// <returns><c>true</c> if parsing succeeded; otherwise <c>false</c>.</returns>
        public static bool TryParse(string? value, [NotNullWhen(true)] out HostnamePortKey? key)
        {
            key = null;
            if (!BindingKeyParser.TryParseHostPort(value, out string? host, out int port))
            {
                return false;
            }

            key = new(host, port);
            return true;
        }

        /// <summary>
        /// Parses a hostname binding key.
        /// </summary>
        /// <param name="value">The textual representation of the key.</param>
        /// <returns>The parsed key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <c>null</c>.</exception>
        /// <exception cref="FormatException">Thrown when <paramref name="value"/> is not a valid hostname binding key.</exception>
        public static HostnamePortKey Parse(string value)
        {
            if (!TryParse(value ?? throw new ArgumentNullException(nameof(value)), out HostnamePortKey? key))
            {
                throw new FormatException(FormatErrorMessage);
            }

            return key;
        }

        /// <inheritdoc />
        public override string ToString() => string.Format(CultureInfo.InvariantCulture, "{0}:{1}", Hostname, Port);

        /// <inheritdoc />
        public override bool Equals(object? obj) => obj switch
        {
            DnsEndPoint endPoint => Equals(endPoint),
            HostnamePortKey key => Equals(key),
            _ => false,
        };

        /// <inheritdoc />
        public override int GetHashCode() => StringComparer.OrdinalIgnoreCase.GetHashCode(Hostname) ^ Port.GetHashCode();

        /// <inheritdoc />
        public bool Equals(HostnamePortKey? other)
        {
            return other != null
                && StringComparer.OrdinalIgnoreCase.Equals(Hostname, other.Hostname)
                && Port == other.Port;
        }

        /// <inheritdoc />
        public bool Equals(DnsEndPoint? other)
        {
            return other != null
                && StringComparer.OrdinalIgnoreCase.Equals(Hostname, other.Host)
                && Port == other.Port;
        }

        /// <summary>
        /// Converts a <see cref="DnsEndPoint"/> to a <see cref="HostnamePortKey"/>.
        /// </summary>
        /// <param name="endPoint">The endpoint to convert.</param>
        public static implicit operator HostnamePortKey?(DnsEndPoint? endPoint) => endPoint == null ? null : From(endPoint);

        /// <summary>
        /// Converts a <see cref="HostnamePortKey"/> to a <see cref="DnsEndPoint"/>.
        /// </summary>
        /// <param name="key">The key to convert.</param>
        public static implicit operator DnsEndPoint?(HostnamePortKey? key) => key?.ToDnsEndPoint();
    }
}
