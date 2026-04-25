using System;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents a scoped central certificate store SSL binding record.
    /// </summary>
    public sealed class ScopedCcsBinding : SslBinding<ScopedCcsKey>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ScopedCcsBinding"/> class.
        /// </summary>
        /// <param name="key">The scoped CCS binding key.</param>
        /// <param name="appId">The application identifier.</param>
        /// <param name="options">The binding options.</param>
        public ScopedCcsBinding(ScopedCcsKey key, Guid appId, BindingOptions? options = null)
            : base(appId, options)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <inheritdoc />
        public override ScopedCcsKey Key { get; }
    }
}
