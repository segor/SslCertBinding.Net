using System;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using NUnit.Framework;

namespace SslCertBinding.Net.Tests
{
    [TestFixture]
    public class SockaddrInteropTests
    {
        [Test]
        public void ReadSockaddrStructPtrRejectsUnsupportedAddressFamily()
        {
            IntPtr ptr = Marshal.AllocCoTaskMem(2);
            try
            {
                Marshal.WriteInt16(ptr, (short)AddressFamily.Unix);

                TargetInvocationException ex = Assert.Throws<TargetInvocationException>(() => InvokeSockaddrInterop("ReadSockaddrStructPtr", ptr));
                Assert.That(ex.InnerException, Is.TypeOf<ArgumentOutOfRangeException>());
            }
            finally
            {
                Marshal.FreeCoTaskMem(ptr);
            }
        }

        [Test]
        public void CreateIPEndPointRejectsUnsupportedAddressFamily()
        {
            object storage = CreateSockaddrStorageStruct((short)AddressFamily.Unix);

            TargetInvocationException ex = Assert.Throws<TargetInvocationException>(() => InvokeSockaddrInterop("CreateIPEndPoint", storage));
            Assert.That(ex.InnerException, Is.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void CreateSockaddrStorageRoundTripsIpv6Endpoint()
        {
            var endpoint = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 8443);

            object storage = InvokeSockaddrInterop("CreateSockaddrStorage", endpoint);
            IPEndPoint roundTripped = (IPEndPoint)InvokeSockaddrInterop("CreateIPEndPoint", storage);

            Assert.That(roundTripped, Is.EqualTo(endpoint));
        }

        [Test]
        public void CreateSockaddrStorageMatchesNativeIpv6Layout()
        {
            var endpoint = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 8443);
            object storage = InvokeSockaddrInterop("CreateSockaddrStorage", endpoint);

            byte[] marshaledBytes = MarshalSockaddrStorage(storage, endpoint.Serialize().Size);
            byte[] expectedBytes = SocketAddressToWindowsBytes(endpoint);

            Assert.That(marshaledBytes, Is.EqualTo(expectedBytes));
        }

        [Test]
        public void CreateIPEndPointReadsNativeIpv6Layout()
        {
            var endpoint = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 8443);
            object storage = CreateSockaddrStorageStruct(SocketAddressToWindowsBytes(endpoint));

            IPEndPoint roundTripped = (IPEndPoint)InvokeSockaddrInterop("CreateIPEndPoint", storage);

            Assert.That(roundTripped, Is.EqualTo(endpoint));
        }

        [Test]
        public void CreateCcsWildcardSockaddrStorageCreatesIpv4WildcardEndpoint()
        {
            const int port = 8443;

            object storage = InvokeSockaddrInterop("CreateCcsWildcardSockaddrStorage", port);
            IPEndPoint roundTripped = (IPEndPoint)InvokeSockaddrInterop("CreateIPEndPoint", storage);

            Assert.That(roundTripped, Is.EqualTo(new IPEndPoint(IPAddress.Any, port)));
        }

        [Test]
        public void CreateCcsWildcardSockaddrStorageMatchesNativeIpv4WildcardLayout()
        {
            var endpoint = new IPEndPoint(IPAddress.Any, 8443);

            object storage = InvokeSockaddrInterop("CreateCcsWildcardSockaddrStorage", endpoint.Port);
            byte[] marshaledBytes = MarshalSockaddrStorage(storage, endpoint.Serialize().Size);
            byte[] expectedBytes = SocketAddressToWindowsBytes(endpoint);

            Assert.That(marshaledBytes, Is.EqualTo(expectedBytes));
        }

        [Test]
        public void CreateSockaddrStructPtrRoundTripsIpv4Endpoint()
        {
            var endpoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 443);
            object[] parameters = { endpoint, null };

            IntPtr ptr = (IntPtr)InvokeSockaddrInterop(
                "CreateSockaddrStructPtr",
                new[] { typeof(IPEndPoint), typeof(Action).MakeByRefType() },
                parameters);
            Action cleanup = (Action)parameters[1];
            try
            {
                IPEndPoint roundTripped = (IPEndPoint)InvokeSockaddrInterop("ReadSockaddrStructPtr", ptr);
                Assert.That(roundTripped, Is.EqualTo(endpoint));
            }
            finally
            {
                cleanup();
            }
        }

        private static object CreateSockaddrStorageStruct(short family)
        {
            Type httpApiType = typeof(SslBindingConfiguration).Assembly.GetType("SslCertBinding.Net.Internal.Interop.HttpApi", throwOnError: true);
            Type storageType = httpApiType.GetNestedType("SOCKADDR_STORAGE", BindingFlags.Public);
            object storage = Activator.CreateInstance(storageType);
            storageType.GetField("ss_family").SetValue(storage, family);
            storageType.GetField("__ss_pad1").SetValue(storage, new byte[6]);
            storageType.GetField("__ss_align").SetValue(storage, 0L);
            storageType.GetField("__ss_pad2").SetValue(storage, new byte[112]);
            return storage;
        }

        private static object CreateSockaddrStorageStruct(byte[] sockaddrBytes)
        {
            Type httpApiType = typeof(SslBindingConfiguration).Assembly.GetType("SslCertBinding.Net.Internal.Interop.HttpApi", throwOnError: true);
            Type storageType = httpApiType.GetNestedType("SOCKADDR_STORAGE", BindingFlags.Public);
            int storageSize = Marshal.SizeOf(storageType);
            byte[] storageBytes = new byte[storageSize];
            Array.Copy(sockaddrBytes, storageBytes, Math.Min(sockaddrBytes.Length, storageBytes.Length));

            GCHandle handle = GCHandle.Alloc(storageBytes, GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure(handle.AddrOfPinnedObject(), storageType);
            }
            finally
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }

        private static byte[] MarshalSockaddrStorage(object storage, int byteCount)
        {
            IntPtr ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.AllocCoTaskMem(Marshal.SizeOf(storage));
                Marshal.StructureToPtr(storage, ptr, false);
                byte[] bytes = new byte[byteCount];
                Marshal.Copy(ptr, bytes, 0, bytes.Length);
                return bytes;
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(ptr, storage.GetType());
                    Marshal.FreeCoTaskMem(ptr);
                }
            }
        }

        private static byte[] SocketAddressToBytes(SocketAddress socketAddress)
        {
            var bytes = new byte[socketAddress.Size];
            for (int index = 0; index < socketAddress.Size; index++)
            {
                bytes[index] = socketAddress[index];
            }

            return bytes;
        }

        private static byte[] SocketAddressToWindowsBytes(IPEndPoint endPoint)
        {
            byte[] bytes = SocketAddressToBytes(endPoint.Serialize());
            byte[] familyBytes = BitConverter.GetBytes((short)endPoint.AddressFamily);
            bytes[0] = familyBytes[0];
            bytes[1] = familyBytes[1];
            return bytes;
        }

        private static object InvokeSockaddrInterop(string methodName, params object[] parameters)
        {
            Type[] parameterTypes = Array.ConvertAll(parameters, parameter => parameter.GetType());
            return InvokeSockaddrInterop(methodName, parameterTypes, parameters);
        }

        private static object InvokeSockaddrInterop(string methodName, Type[] parameterTypes, params object[] parameters)
        {
            Type interopType = typeof(SslBindingConfiguration).Assembly.GetType("SslCertBinding.Net.Internal.Interop.SockaddrInterop", throwOnError: true);
            MethodInfo method = interopType.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static, null, parameterTypes, null);
            return method.Invoke(null, parameters);
        }
    }
}
