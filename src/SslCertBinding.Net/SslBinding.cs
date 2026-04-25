using System;

namespace SslCertBinding.Net
{
    /// <summary>
    /// Represents an SSL binding record with a strongly typed binding key.
    /// </summary>
    /// <typeparam name="TKey">The concrete binding key type.</typeparam>
    public abstract class SslBinding<TKey> : ISslBinding
        where TKey : SslBindingKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SslBinding{TKey}"/> class.
        /// </summary>
        /// <param name="appId">The application identifier that owns the binding.</param>
        /// <param name="options">The binding options.</param>
        protected SslBinding(Guid appId, BindingOptions? options = null)
        {
            AppId = appId;
            Options = options ?? new();
        }

        /// <inheritdoc />
        public virtual SslBindingKind Kind => Key.Kind;

        /// <inheritdoc cref="ISslBinding.Key" />
        public abstract TKey Key { get; }

        SslBindingKey ISslBinding.Key => Key;

        /// <inheritdoc />
        public Guid AppId { get; }

        /// <inheritdoc />
        public BindingOptions Options { get; }
    }
}
