using System;

namespace SslCertBinding.Net
{
    internal static class ArgumentValidation
    {
        public static T ThrowIfNull<T>(this T arg, string paramName) where T : class
        {
            return arg is null ? throw new ArgumentNullException(paramName) : arg;
        }
    }
}
