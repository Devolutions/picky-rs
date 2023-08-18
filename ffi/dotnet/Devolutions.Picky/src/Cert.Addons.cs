using System.Security.Cryptography.X509Certificates;

namespace Devolutions.Picky;

public partial class Cert
{
    public X509Certificate2 ToX509Certificate2()
    {
		byte[] rawData = ToPem().ToData();
		return new X509Certificate2(rawData);
    }

    public static Cert FromX509Certificate2(X509Certificate2 cert)
    {
        return FromDer(cert.RawData);
    }
}
