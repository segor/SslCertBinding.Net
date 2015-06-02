using System.Net;

namespace SslCertBinding.Net
{
	public interface ICertificateBindingConfiguration
	{
		CertificateBinding[] Query(IPEndPoint ipPort = null);
		bool Bind(CertificateBinding binding);
		void Delete(IPEndPoint endPoint);
		void Delete(IPEndPoint[] endPoints);
	}
}