using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net
{
	/// <summary>
	/// Defines a record in the SSL configuration store
	/// </summary>
	public class CertificateBinding
	{
		/// <summary>
		/// A string representation the SSL certificate hash. 
		/// </summary>
		public string Thumbprint { get; private set; }

		/// <summary>
		/// The name of the store from which the server certificate is to be read. If set to NULL, "MY" is assumed as the default name. 
		/// The specified certificate store name must be present in the Local Machine store location.
		/// </summary>
		public string StoreName { get; private set; }

		/// <summary>
		/// An IP address and port with which this SSL certificate is associated. 
		/// If the <see cref="IPEndPoint.Address"/> property is set to 0.0.0.0, the certificate is applicable to all IPv4 and IPv6 addresses. If the <see cref="IPEndPoint.Address"/> property is set to [::], the certificate is applicable to all IPv6 addresses.
		/// </summary>
		public IPEndPoint IpPort { get; private set; }

		/// <summary>
		/// A unique identifier of the application setting this record.
		/// </summary>
		public Guid AppId { get; private set; }

		/// <summary>
		/// Additional options.
		/// </summary>
		public BindingOptions Options { get; private set; }

		public CertificateBinding(string certificateThumbprint, StoreName certificateStoreName, IPEndPoint ipPort, Guid appId, BindingOptions options = null)
			: this(certificateThumbprint, certificateStoreName.ToString(), ipPort, appId, options) { }

		public CertificateBinding(string certificateThumbprint, string certificateStoreName, IPEndPoint ipPort, Guid appId, BindingOptions options = null) {

			if (certificateThumbprint == null) throw new ArgumentNullException("certificateThumbprint");
			if (ipPort == null) throw new ArgumentNullException("ipPort");

			if (certificateStoreName == null) {
				// StoreName of null is assumed to be My / Personal
				// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364647(v=vs.85).aspx
				certificateStoreName = "MY";
			}

			Thumbprint = certificateThumbprint;
			StoreName = certificateStoreName;
			IpPort = ipPort;
			AppId = appId;
			Options = options ?? new BindingOptions();
		}
	}
}