using System;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents an SSL binding record.
    /// </summary>
    public interface ISslBinding
    {
        /// <summary>
        /// Gets the binding family.
        /// </summary>
        SslBindingKind Kind { get; }

        /// <summary>
        /// Gets the binding key.
        /// </summary>
        SslBindingKey Key { get; }

        /// <summary>
        /// Gets the application identifier that owns the binding.
        /// </summary>
        Guid AppId { get; }

        /// <summary>
        /// Gets the binding options.
        /// </summary>
        BindingOptions Options { get; }
    }
}
