using System;
using System.ComponentModel;
using System.Reflection;
using NUnit.Framework;

#nullable disable
namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    public class HttpApiTests
    {
        [Test]
        public void ThrowWin32ExceptionIfErrorWithNoErrorDoesNotThrow()
        {
            Assert.DoesNotThrow(() => InvokeHttpApiVoid("ThrowWin32ExceptionIfError", 0u));
        }

        [Test]
        public void ThrowWin32ExceptionIfErrorWithNonZeroErrorThrowsWin32Exception()
        {
            TargetInvocationException ex = Assert.Throws<TargetInvocationException>(() => InvokeHttpApiVoid("ThrowWin32ExceptionIfError", 5u));

            Assert.Multiple(() =>
            {
                Assert.That(ex.InnerException, Is.TypeOf<Win32Exception>());
                Assert.That(((Win32Exception)ex.InnerException).NativeErrorCode, Is.EqualTo(5));
            });
        }

        private static void InvokeHttpApiVoid(string methodName, params object[] parameters)
        {
            Type httpApiType = typeof(SslBindingConfiguration).Assembly.GetType("SslCertBinding.Net.Internal.Interop.HttpApi", throwOnError: true);
            MethodInfo method = httpApiType.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static);
            method.Invoke(null, parameters);
        }
    }
}
