using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net
{
	public class CertificateBindingInfo
	{
		public string Thumbprint { get; private set; }
		public string StoreName { get; private set; }
		public IPEndPoint IpPort { get; private set; }
		public Guid AppId { get; private  set; }

		public CertificateBindingInfo(string certificateThumbprint, StoreName certificateStoreName, IPEndPoint ipPort, Guid appId)
			: this(certificateThumbprint, certificateStoreName.ToString(), ipPort, appId) { }

		public CertificateBindingInfo(string certificateThumbprint, string certificateStoreName, IPEndPoint ipPort, Guid appId) {

			if (certificateThumbprint == null) throw new ArgumentNullException("certificateThumbprint");
			if (ipPort == null) throw new ArgumentNullException("ipPort");

            if (certificateStoreName == null)
            {
                // StoreName of null is assumed to be My / Personal
                // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364647(v=vs.85).aspx
                certificateStoreName = "My";
            }

			Thumbprint = certificateThumbprint;
			StoreName = certificateStoreName;
			IpPort = ipPort;
			AppId = appId;
		}
	}
}