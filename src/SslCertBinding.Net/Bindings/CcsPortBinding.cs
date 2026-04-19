using System;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents a central certificate store SSL binding record.
    /// </summary>
    public sealed class CcsPortBinding : SslBinding<CcsPortKey>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CcsPortBinding"/> class.
        /// </summary>
        /// <param name="key">The CCS binding key.</param>
        /// <param name="appId">The application identifier.</param>
        /// <param name="options">The binding options.</param>
        public CcsPortBinding(CcsPortKey key, Guid appId, BindingOptions options = null)
            : base(appId, options)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <inheritdoc />
        public override CcsPortKey Key { get; }
    }
}
