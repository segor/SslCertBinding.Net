using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace SslCertBinding.Net.Tests
{
    internal static class ProcessExtensions
    {
#if NET462_OR_GREATER
        public static async Task WaitForExitAsync(this Process process, CancellationToken cancellationToken = default)
        {
            while (!process.HasExited)
            {
                await Task.Delay(100, cancellationToken);
            }
        }
#endif
    }
}
