using System;

namespace SslCertBinding.Net.Internal
{
    internal static class PlatformHelpers
    {
        private const string WindowsOnlyMessage = "Windows HTTP Server API is not supported on this platform.";

        public static void ThrowIfNotWindows()
        {
#if NET5_0_OR_GREATER
            if (!OperatingSystem.IsWindows())
            {
                throw CreateWindowsOnlyException();
            }
#endif
        }

        public static PlatformNotSupportedException CreateWindowsOnlyException(Exception innerException = null)
            => new PlatformNotSupportedException(WindowsOnlyMessage, innerException);
    }
}
