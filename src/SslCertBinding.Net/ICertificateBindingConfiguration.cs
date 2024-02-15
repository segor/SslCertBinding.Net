using System.Collections.Generic;
using System.Net;

namespace SslCertBinding.Net
{
    public interface ICertificateBindingConfiguration
    {
        IReadOnlyList<CertificateBinding> Query(IPEndPoint ipPort = null);
        void Bind(CertificateBinding binding);
        void Delete(IPEndPoint endPoint);
        void Delete(IReadOnlyCollection<IPEndPoint> endPoints);
    }
}