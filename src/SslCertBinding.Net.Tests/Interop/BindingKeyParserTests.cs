using System;
using System.Net;
using System.Reflection;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    public class BindingKeyParserTests
    {
        [TestCase(-1, false)]
        [TestCase(0, true)]
        [TestCase(65535, true)]
        [TestCase(65536, false)]
        public void IsValidPortReturnsExpectedValue(int port, bool expected)
        {
            object result = InvokeBindingKeyParser("IsValidPort", port);

            Assert.That(result, Is.EqualTo(expected));
        }

        [TestCase(null, false, null, 0, TestName = "TryParseIpPort_Null")]
        [TestCase("   ", false, null, 0, TestName = "TryParseIpPort_Whitespace")]
        [TestCase("[::1", false, null, 0, TestName = "TryParseIpPort_MissingClosingBracket")]
        [TestCase("[::1]443", false, null, 0, TestName = "TryParseIpPort_MissingSeparatorAfterBracket")]
        [TestCase("::1:443", false, null, 0, TestName = "TryParseIpPort_UnbracketedIpv6Rejected")]
        [TestCase("localhost:443", false, null, 443, TestName = "TryParseIpPort_HostnameRejected")]
        [TestCase("127.0.0.1:abc", false, null, 0, TestName = "TryParseIpPort_InvalidPortRejected")]
        [TestCase(" [2001:db8::1]:443 ", true, "2001:db8::1", 443, TestName = "TryParseIpPort_OuterWhitespaceAccepted")]
        [TestCase("[2001:db8::1] :443 ", false, null, 0, TestName = "TryParseIpPort_WhitespaceBeforeSeparatorRejected")]
        [TestCase("[2001:db8::1]: 443 ", false, null, 0, TestName = "TryParseIpPort_WhitespaceAfterSeparatorRejected")]
        [TestCase("[2001:db8::1]:443", true, "2001:db8::1", 443, TestName = "TryParseIpPort_BracketedIpv6Accepted")]
        public void TryParseIpPortHandlesExpectedCases(string? value, bool expectedResult, string? expectedAddress, int expectedPort)
        {
            object?[] parameters = { value, null, 0 };
            bool result = (bool)InvokeBindingKeyParser("TryParseIpPort", parameters);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.EqualTo(expectedResult));
                Assert.That(parameters[1] as IPAddress, Is.EqualTo(expectedAddress == null ? null : IPAddress.Parse(expectedAddress)));
                Assert.That(parameters[2], Is.EqualTo(expectedPort));
            });
        }

        [TestCase(null, false, null, 0, TestName = "TryParseHostPort_Null")]
        [TestCase("   ", false, null, 0, TestName = "TryParseHostPort_Whitespace")]
        [TestCase("localhost", false, null, 0, TestName = "TryParseHostPort_MissingSeparator")]
        [TestCase(":443", false, null, 0, TestName = "TryParseHostPort_EmptyHost")]
        [TestCase("localhost:", false, null, 0, TestName = "TryParseHostPort_EmptyPort")]
        [TestCase("[localhost]:443", false, null, 0, TestName = "TryParseHostPort_BracketedHostRejected")]
        [TestCase("www.contoso.com:abc", false, null, 0, TestName = "TryParseHostPort_InvalidPortRejected")]
        [TestCase("foo:bar:443", false, null, 0, TestName = "TryParseHostPort_EmbeddedColonRejected")]
        [TestCase("foo bar:443", false, null, 0, TestName = "TryParseHostPort_WhitespaceInHostRejected")]
        [TestCase("  www.contoso.com:443  ", true, "www.contoso.com", 443, TestName = "TryParseHostPort_OuterWhitespaceAccepted")]
        [TestCase("  www.contoso.com :443  ", false, null, 0, TestName = "TryParseHostPort_WhitespaceBeforeSeparatorRejected")]
        [TestCase("  www.contoso.com: 443  ", false, null, 0, TestName = "TryParseHostPort_WhitespaceAfterSeparatorRejected")]
        [TestCase("*.example.com:443", true, "*.example.com", 443, TestName = "TryParseHostPort_WildcardAccepted")]
        public void TryParseHostPortHandlesExpectedCases(string? value, bool expectedResult, string? expectedHost, int expectedPort)
        {
            object?[] parameters = { value, null, 0 };
            bool result = (bool)InvokeBindingKeyParser("TryParseHostPort", parameters);

            Assert.Multiple(() =>
            {
                Assert.That(result, Is.EqualTo(expectedResult));
                Assert.That(parameters[1] as string, Is.EqualTo(expectedHost));
                Assert.That(parameters[2], Is.EqualTo(expectedPort));
            });
        }

        private static object InvokeBindingKeyParser(string methodName, params object?[] parameters)
        {
            Type parserType = typeof(SslBindingConfiguration).Assembly.GetType("SslCertBinding.Net.Internal.BindingKeyParser", throwOnError: true)!;
            MethodInfo method = parserType.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static)!;
            return method.Invoke(null, parameters)!;
        }
    }
}
