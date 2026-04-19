namespace SslCertBinding.Net
{
    /// <summary>
    /// Identifies the HTTP SSL binding family.
    /// </summary>
    public enum SslBindingKind
    {
        /// <summary>
        /// An SSL binding keyed by IP address and port.
        /// </summary>
        IpPort = 0,

        /// <summary>
        /// An SSL binding keyed by hostname and port.
        /// </summary>
        HostnamePort = 1,

        /// <summary>
        /// A central certificate store SSL binding keyed by port.
        /// </summary>
        CcsPort = 2,

        /// <summary>
        /// A scoped central certificate store SSL binding keyed by hostname and port.
        /// </summary>
        ScopedCcs = 3,
    }
}
