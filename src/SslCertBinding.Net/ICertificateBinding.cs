using System.Net;

namespace SslCertBinding.Net
{
	public interface ICertificateBinding
	{
		CertificateBindingInfo QueryBinding(IPEndPoint ipPort);
		void Bind(CertificateBindingInfo binding);
		void DeleteBinding(IPEndPoint endPoint);
		void DeleteBinding(IPEndPoint[] endPoints);
		CertificateBindingInfo[] QueryBinding();
	}
}