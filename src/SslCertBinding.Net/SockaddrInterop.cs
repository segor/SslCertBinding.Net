using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace SslCertBinding.Net
{
    internal static class SockaddrInterop
    {
        /// <summary>
        /// Creates an unmanaged sockaddr structure to pass to a WinAPI function.
        /// </summary>
        /// <param name="ipEndPoint">IP address and port number</param>
        /// <returns>a handle for the structure. Use the AddrOfPinnedObject Method to get a stable pointer to the object. </returns>
        /// <remarks>When the handle goes out of scope you must explicitly release it by calling the Free method; otherwise, memory leaks may occur. </remarks>
        public static GCHandle CreateSockaddrStructure(IPEndPoint ipEndPoint)
        {
            SocketAddress socketAddress = ipEndPoint.Serialize();

            // use an array of bytes instead of the sockaddr structure 
            byte[] sockAddrStructureBytes = new byte[socketAddress.Size];
            GCHandle sockAddrHandle = GCHandle.Alloc(sockAddrStructureBytes, GCHandleType.Pinned);
            for (int i = 0; i < socketAddress.Size; ++i)
            {
                sockAddrStructureBytes[i] = socketAddress[i];
            }
            return sockAddrHandle;
        }


        /// <summary>
        /// Reads the unmanaged sockaddr structure returned by a WinAPI function
        /// </summary>
        /// <param name="pSockaddrStructure">pointer to the unmanaged sockaddr structure</param>
        /// <returns>IP address and port number</returns>
        public static IPEndPoint ReadSockaddrStructure(IntPtr pSockaddrStructure)
        {
            short sAddressFamily = Marshal.ReadInt16(pSockaddrStructure);
            AddressFamily addressFamily = (AddressFamily)sAddressFamily;

            int sockAddrSructureSize;
            IPEndPoint ipEndPointAny;
            switch (addressFamily)
            {
                case AddressFamily.InterNetwork:
                    // IP v4 address
                    sockAddrSructureSize = 16;
                    ipEndPointAny = new IPEndPoint(IPAddress.Any, 0);
                    break;
                case AddressFamily.InterNetworkV6:
                    // IP v6 address
                    sockAddrSructureSize = 28;
                    ipEndPointAny = new IPEndPoint(IPAddress.IPv6Any, 0);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(pSockaddrStructure), $"Unsupported address family: {addressFamily}");
            }


            // get bytes of the sockadrr structure
            byte[] sockAddrSructureBytes = new byte[sockAddrSructureSize];
            Marshal.Copy(pSockaddrStructure, sockAddrSructureBytes, 0, sockAddrSructureSize);

            // create SocketAddress from bytes
            var socketAddress = new SocketAddress(AddressFamily.Unspecified, sockAddrSructureSize);
            for (int i = 0; i < sockAddrSructureSize; i++)
            {
                socketAddress[i] = sockAddrSructureBytes[i];
            }

            // create IPEndPoint from SocketAddress
            IPEndPoint result = (IPEndPoint)ipEndPointAny.Create(socketAddress);

            return result;
        }


        /// <summary>
        /// Creates a SOCKADDR_STORAGE structure for the specified port number.
        /// </summary>
        public static HttpApi.SOCKADDR_STORAGE CreateSockaddrStorage(int port)
        {
            return CreateSockaddrStorage(new IPEndPoint(IPAddress.Any, port));
        }


        /// <summary>
        /// Creates a SOCKADDR_STORAGE structure from an IPEndPoint.
        /// </summary>
        public static HttpApi.SOCKADDR_STORAGE CreateSockaddrStorage(IPEndPoint ipEndPoint)
        {
            var result = new HttpApi.SOCKADDR_STORAGE();
            var socketAddress = ipEndPoint.Serialize();

            // Set address family
            result.ss_family = (short)ipEndPoint.AddressFamily;

            // Fill __ss_pad1 (first 6 bytes after family)
            result.__ss_pad1 = new byte[6];
            for (int i = 2; i < 8 && i < socketAddress.Size; i++)
            {
                result.__ss_pad1[i - 2] = socketAddress[i];
            }

            // Fill __ss_pad2 (remaining bytes, up to 112)
            result.__ss_pad2 = new byte[112];
            for (int i = 8; i < socketAddress.Size && (i - 8) < result.__ss_pad2.Length; i++)
            {
                result.__ss_pad2[i - 8] = socketAddress[i];
            }

            // Alignment field is left as default (0)
            return result;
        }

        /// <summary>
        /// Creates an IPEndPoint from a SOCKADDR_STORAGE structure.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">The structure contains an unsupported address family</exception>
        public static IPEndPoint CreateIPEndPoint(HttpApi.SOCKADDR_STORAGE storage)
        {
            // Determine address family and structure size
            AddressFamily family = (AddressFamily)storage.ss_family;
            int size = family == AddressFamily.InterNetwork ? 16 :
                       family == AddressFamily.InterNetworkV6 ? 28 :
                       throw new ArgumentOutOfRangeException(nameof(storage), $"Unsupported address family: {family}");

            // Compose the raw bytes for SocketAddress
            byte[] bytes = new byte[size];
            bytes[0] = (byte)(storage.ss_family & 0xFF);
            bytes[1] = (byte)((storage.ss_family >> 8) & 0xFF);
            for (int i = 0; i < 6 && (i + 2) < size; i++)
                bytes[i + 2] = storage.__ss_pad1[i];
            for (int i = 0; i < storage.__ss_pad2.Length && (i + 8) < size; i++)
                bytes[i + 8] = storage.__ss_pad2[i];

            // Create SocketAddress and IPEndPoint
            var socketAddress = new SocketAddress(family, size);
            for (int i = 0; i < size; i++)
                socketAddress[i] = bytes[i];

            IPEndPoint anyEp = family == AddressFamily.InterNetwork
                ? new IPEndPoint(IPAddress.Any, 0)
                : new IPEndPoint(IPAddress.IPv6Any, 0);

            return (IPEndPoint)anyEp.Create(socketAddress);
        }
    }
}
