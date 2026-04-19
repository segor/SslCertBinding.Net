using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using SslCertBinding.Net.Internal;

namespace SslCertBinding.Net.Internal.Interop
{
    internal static class SockaddrInterop
    {
        private static readonly int SockaddrStorageSize = Marshal.SizeOf<HttpApi.SOCKADDR_STORAGE>();

        /// <summary>
        /// Creates an unmanaged sockaddr structure to pass to a WinAPI function.
        /// </summary>
        /// <param name="ipEndPoint">IP address and port number.</param>
        /// <param name="freeResourcesFunc">Function to free unmanaged resources.</param>
        /// <returns>Pointer to the unmanaged sockaddr structure.</returns>
        public static IntPtr CreateSockaddrStructPtr(IPEndPoint ipEndPoint, out Action freeResourcesFunc)
        {
            byte[] sockaddrBytes = CreateSockaddrBytes(ipEndPoint);
            GCHandle handle = GCHandle.Alloc(sockaddrBytes, GCHandleType.Pinned);

            freeResourcesFunc = () =>
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            };

            return handle.AddrOfPinnedObject();
        }

        /// <summary>
        /// Reads the unmanaged sockaddr structure returned by a WinAPI function.
        /// </summary>
        /// <param name="sockaddrStructPtr">Pointer to the unmanaged sockaddr structure.</param>
        /// <returns>IP address and port number.</returns>
        public static IPEndPoint ReadSockaddrStructPtr(IntPtr sockaddrStructPtr)
        {
            short addressFamilyValue = Marshal.ReadInt16(sockaddrStructPtr);
            AddressFamily addressFamily = (AddressFamily)addressFamilyValue;

            int sockaddrSize;
            IPEndPoint anyEndPoint;
            switch (addressFamily)
            {
                case AddressFamily.InterNetwork:
                    sockaddrSize = 16;
                    anyEndPoint = new(IPAddress.Any, 0);
                    break;
                case AddressFamily.InterNetworkV6:
                    sockaddrSize = 28;
                    anyEndPoint = new(IPAddress.IPv6Any, 0);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(sockaddrStructPtr), $"Unsupported address family: {addressFamily}");
            }

            byte[] sockaddrBytes = new byte[sockaddrSize];
            Marshal.Copy(sockaddrStructPtr, sockaddrBytes, 0, sockaddrSize);

            var socketAddress = new SocketAddress(addressFamily, sockaddrSize);
            for (int index = 2; index < sockaddrSize; index++)
            {
                socketAddress[index] = sockaddrBytes[index];
            }

            return (IPEndPoint)anyEndPoint.Create(socketAddress);
        }

        /// <summary>
        /// Creates a SOCKADDR_STORAGE structure for the specified port number.
        /// </summary>
        /// <param name="port">The port number.</param>
        /// <returns>The sockaddr storage structure.</returns>
        public static HttpApi.SOCKADDR_STORAGE CreateSockaddrStorage(int port)
        {
            return CreateSockaddrStorage(new IPEndPoint(IPAddress.Any, port));
        }

        /// <summary>
        /// Creates the IPv4 wildcard sockaddr required by HTTP.sys for plain CCS bindings.
        /// </summary>
        /// <param name="port">The port number.</param>
        /// <returns>The sockaddr storage structure.</returns>
        public static HttpApi.SOCKADDR_STORAGE CreateCcsWildcardSockaddrStorage(int port)
        {
            if (port < IPEndPoint.MinPort || port > IPEndPoint.MaxPort)
            {
                throw new ArgumentOutOfRangeException(nameof(port));
            }

            byte[] storageBytes = new byte[SockaddrStorageSize];
            byte[] familyBytes = BitConverter.GetBytes((short)AddressFamily.InterNetwork);
            byte[] portBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)port));

            storageBytes[0] = familyBytes[0];
            storageBytes[1] = familyBytes[1];
            storageBytes[2] = portBytes[0];
            storageBytes[3] = portBytes[1];

            return CreateSockaddrStorage(storageBytes);
        }

        /// <summary>
        /// Creates a SOCKADDR_STORAGE structure from an endpoint.
        /// </summary>
        /// <param name="ipEndPoint">The endpoint to convert.</param>
        /// <returns>The sockaddr storage structure.</returns>
        public static HttpApi.SOCKADDR_STORAGE CreateSockaddrStorage(IPEndPoint ipEndPoint)
        {
            ThrowHelper.ThrowIfNull(ipEndPoint, nameof(ipEndPoint));

            byte[] storageBytes = new byte[SockaddrStorageSize];
            byte[] sockaddrBytes = CreateSockaddrBytes(ipEndPoint);
            for (int index = 0; index < sockaddrBytes.Length && index < storageBytes.Length; index++)
            {
                storageBytes[index] = sockaddrBytes[index];
            }

            return CreateSockaddrStorage(storageBytes);
        }

        private static HttpApi.SOCKADDR_STORAGE CreateSockaddrStorage(byte[] storageBytes)
        {
            GCHandle handle = GCHandle.Alloc(storageBytes, GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure<HttpApi.SOCKADDR_STORAGE>(handle.AddrOfPinnedObject());
            }
            finally
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }

        /// <summary>
        /// Creates an endpoint from a SOCKADDR_STORAGE structure.
        /// </summary>
        /// <param name="storage">The sockaddr storage structure.</param>
        /// <returns>The endpoint represented by the storage.</returns>
        public static IPEndPoint CreateIPEndPoint(HttpApi.SOCKADDR_STORAGE storage)
        {
            AddressFamily family = (AddressFamily)storage.ss_family;
            int size;
            switch (family)
            {
                case AddressFamily.InterNetwork:
                    size = 16;
                    break;
                case AddressFamily.InterNetworkV6:
                    size = 28;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(storage), $"Unsupported address family: {family}");
            }

            IntPtr storagePtr = Marshal.AllocCoTaskMem(SockaddrStorageSize);
            var socketAddress = new SocketAddress(family, size);
            try
            {
                Marshal.StructureToPtr(storage, storagePtr, false);
                byte[] sockaddrBytes = new byte[size];
                Marshal.Copy(storagePtr, sockaddrBytes, 0, sockaddrBytes.Length);
                for (int index = 2; index < sockaddrBytes.Length; index++)
                {
                    socketAddress[index] = sockaddrBytes[index];
                }
            }
            finally
            {
                Marshal.DestroyStructure<HttpApi.SOCKADDR_STORAGE>(storagePtr);
                Marshal.FreeCoTaskMem(storagePtr);
            }

            IPEndPoint anyEndPoint = family == AddressFamily.InterNetwork
                ? new(IPAddress.Any, 0)
                : new(IPAddress.IPv6Any, 0);
            return (IPEndPoint)anyEndPoint.Create(socketAddress);
        }

        private static byte[] CreateSockaddrBytes(IPEndPoint ipEndPoint)
        {
            SocketAddress socketAddress = ipEndPoint.Serialize();
            byte[] sockaddrBytes = new byte[socketAddress.Size];
            for (int index = 2; index < socketAddress.Size; index++)
            {
                sockaddrBytes[index] = socketAddress[index];
            }

            byte[] familyBytes = BitConverter.GetBytes((short)ipEndPoint.AddressFamily);
            sockaddrBytes[0] = familyBytes[0];
            sockaddrBytes[1] = familyBytes[1];
            return sockaddrBytes;
        }
    }
}
