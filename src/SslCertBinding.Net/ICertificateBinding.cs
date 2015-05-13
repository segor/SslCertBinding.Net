using System.Net;

namespace SslCertBinding.Net
{
	public interface ICertificateBinding
	{
		CertificateBindingInfo[] Query(IPEndPoint ipPort = null);
		bool Bind(CertificateBindingInfo binding);
		void Delete(IPEndPoint endPoint);
		void Delete(IPEndPoint[] endPoints);
	}
}