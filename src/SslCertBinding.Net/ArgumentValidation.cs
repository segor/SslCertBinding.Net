using System;
using System.Runtime.CompilerServices;

namespace SslCertBinding.Net
{
    internal static class ArgumentValidation
    {
        /// <summary>
        /// Throws an <see cref="ArgumentNullException"/> if the argument is null.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="arg"></param>
        /// <param name="paramName"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static T ThrowIfNull<T>(this T arg, string paramName) where T : class
        {
            return arg is null ? throw new ArgumentNullException(paramName) : arg;
        }

        /// <summary>
        /// Throws an <see cref="ArgumentException"/> if the string argument is null or empty.
        /// </summary>
        /// <param name="arg"></param>
        /// <param name="paramName"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ThrowIfNullOrEmpty(this string arg, string paramName)
        {
            return string.IsNullOrEmpty(arg) ? throw new ArgumentException("Value cannot be null or empty.", paramName) : arg;
        }
    }
}
