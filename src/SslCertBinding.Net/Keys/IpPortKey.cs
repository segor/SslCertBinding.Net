using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using SslCertBinding.Net.Internal;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents the key for an IP-based SSL binding.
    /// </summary>
    public sealed class IpPortKey : SslBindingKey, IEquatable<IpPortKey>, IEquatable<IPEndPoint>
    {
        private const string FormatErrorMessage = "Invalid IP binding key format.";

        /// <summary>
        /// Initializes a new instance of the <see cref="IpPortKey"/> class.
        /// </summary>
        /// <param name="address">The bound IP address.</param>
        /// <param name="port">The bound port.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="address"/> is <c>null</c>.</exception>
        public IpPortKey(IPAddress address, int port)
            : this(new IPEndPoint(address ?? throw new ArgumentNullException(nameof(address)), port))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="IpPortKey"/> class.
        /// </summary>
        /// <param name="endPoint">The bound endpoint.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="endPoint"/> is <c>null</c>.</exception>
        public IpPortKey(IPEndPoint endPoint)
        {
            ThrowHelper.ThrowIfNull(endPoint, nameof(endPoint));

            Address = endPoint.Address;
            Port = endPoint.Port;
        }

        /// <inheritdoc />
        public override SslBindingKind Kind => SslBindingKind.IpPort;

        /// <summary>
        /// Gets the bound IP address.
        /// </summary>
        public IPAddress Address { get; }

        /// <summary>
        /// Gets the bound port.
        /// </summary>
        public int Port { get; }

        /// <summary>
        /// Creates an <see cref="IPEndPoint"/> from this key.
        /// </summary>
        /// <returns>The corresponding endpoint.</returns>
        public IPEndPoint ToIPEndPoint() => new(Address, Port);

        /// <summary>
        /// Creates a binding key from an <see cref="IPEndPoint"/>.
        /// </summary>
        /// <param name="endPoint">The endpoint to convert.</param>
        /// <returns>The converted key.</returns>
        public static IpPortKey From(IPEndPoint endPoint) => new(endPoint);

        /// <summary>
        /// Tries to parse an IP binding key.
        /// </summary>
        /// <param name="value">The textual representation of the key.</param>
        /// <param name="key">When this method returns, contains the parsed key if parsing succeeded.</param>
        /// <returns><c>true</c> if parsing succeeded; otherwise <c>false</c>.</returns>
        public static bool TryParse(string? value, [NotNullWhen(true)] out IpPortKey? key)
        {
            key = null;
            if (!BindingKeyParser.TryParseIpPort(value, out IPAddress? address, out int port))
            {
                return false;
            }

            key = new(address, port);
            return true;
        }

        /// <summary>
        /// Parses an IP binding key.
        /// </summary>
        /// <param name="value">The textual representation of the key.</param>
        /// <returns>The parsed key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <c>null</c>.</exception>
        /// <exception cref="FormatException">Thrown when <paramref name="value"/> is not a valid IP binding key.</exception>
        public static IpPortKey Parse(string value)
        {
            if (!TryParse(value ?? throw new ArgumentNullException(nameof(value)), out IpPortKey? key))
            {
                throw new FormatException(FormatErrorMessage);
            }

            return key;
        }

        /// <inheritdoc />
        public override string ToString() => ToIPEndPoint().ToString();

        /// <inheritdoc />
        public override bool Equals(object? obj) => obj switch
        {
            IPEndPoint endPoint => Equals(endPoint),
            IpPortKey key => Equals(key),
            _ => false,
        };

        /// <inheritdoc />
        public override int GetHashCode() => ToIPEndPoint().GetHashCode();

        /// <inheritdoc />
        public bool Equals(IpPortKey? other)
        {
            return other != null && Address.Equals(other.Address) && Port == other.Port;
        }

        /// <inheritdoc />
        public bool Equals(IPEndPoint? other)
        {
            return other != null && ToIPEndPoint().Equals(other);
        }

        /// <summary>
        /// Converts an <see cref="IPEndPoint"/> to an <see cref="IpPortKey"/>.
        /// </summary>
        /// <param name="endPoint">The endpoint to convert.</param>
        public static implicit operator IpPortKey?(IPEndPoint? endPoint) => endPoint == null ? null : From(endPoint);

        /// <summary>
        /// Converts an <see cref="IpPortKey"/> to an <see cref="IPEndPoint"/>.
        /// </summary>
        /// <param name="key">The key to convert.</param>
        public static implicit operator IPEndPoint?(IpPortKey? key) => key?.ToIPEndPoint();
    }
}
