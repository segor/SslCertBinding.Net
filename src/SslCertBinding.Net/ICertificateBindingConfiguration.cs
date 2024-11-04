using System.Collections.Generic;
using System.Net;

namespace SslCertBinding.Net
{
    public interface ICertificateBindingConfiguration
    {
        IReadOnlyList<CertificateBinding> Query(DnsEndPoint endPoint = null);
        void Bind(CertificateBinding binding);
        void Delete(DnsEndPoint endPoint);
        void Delete(IReadOnlyCollection<DnsEndPoint> endPoints);
    }
}