using System;

namespace SslCertBinding.Net.Internal
{
    internal static class ThrowHelper
    {
        public static void ThrowIfNull(object value, string paramName)
        {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(value, paramName);
#else
#pragma warning disable CA1510
            if (value == null)
            {
                throw new ArgumentNullException(paramName);
            }
#pragma warning restore CA1510
#endif
        }
    }
}
