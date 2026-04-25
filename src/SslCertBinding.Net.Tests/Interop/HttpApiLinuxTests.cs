#if NET5_0_OR_GREATER
#pragma warning disable CA1416 // Validate platform compatibility
using System;
using System.Reflection;
using NUnit.Framework;

#nullable disable
namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public class HttpApiLinuxTests
    {
        [Test]
        public void CallHttpApiOnLinuxThrowsPlatformNotSupportedExceptionAndDoesNotInvokeBody()
        {
            bool bodyCalled = false;

            TargetInvocationException ex = Assert.Throws<TargetInvocationException>(
                () => InvokeCallHttpApi(
                    new Action(
                        () =>
                        {
                            bodyCalled = true;
                        })));

            Assert.Multiple(() =>
            {
                Assert.That(ex.InnerException, Is.TypeOf<PlatformNotSupportedException>());
                Assert.That(ex.InnerException.InnerException, Is.Null);
                Assert.That(bodyCalled, Is.False);
            });
        }

        private static void InvokeCallHttpApi(Action body)
        {
            Type httpApiType = typeof(SslBindingConfiguration).Assembly.GetType("SslCertBinding.Net.Internal.Interop.HttpApi", throwOnError: true);
            MethodInfo method = httpApiType.GetMethod("CallHttpApi", BindingFlags.Public | BindingFlags.Static);
            method.Invoke(null, new object[] { body });
        }
    }
}
#pragma warning restore CA1416 // Validate platform compatibility
#endif
