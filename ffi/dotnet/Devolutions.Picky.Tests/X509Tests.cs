using System;
using System.Security.Cryptography.X509Certificates;

using Xunit;

namespace Devolutions.Picky.Tests;

public class X509Tests
{
    private static readonly string certPemRepr = @"-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----";

    [Fact]
    public void KeyIdAndExpirationDate()
    {
        Pem pem = Pem.Parse(certPemRepr);
        Cert cert = Cert.FromPem(pem);
        UtcDate expirationDate = cert.ValidNotAfter;
        UtcDate notBeforeDate = cert.ValidNotBefore;

        Assert.Equal(CertType.Root, cert.Ty);

        Assert.Equal("c4a7b1a47b2c71fadbe14b9075ffc41560858910", cert.SubjectKeyIdHex);

        Assert.Equal(2021, expirationDate.Year);
        Assert.Equal(09, expirationDate.Month);
        Assert.Equal(30, expirationDate.Day);

        Assert.Equal(2000, notBeforeDate.Year);
        Assert.Equal(09, notBeforeDate.Month);
        Assert.Equal(30, notBeforeDate.Day);
    }

    [Fact]
    public void X509Certificate2Conversion()
    {
        Pem pem = Pem.Parse(certPemRepr);
        Cert cert = Cert.FromPem(pem);
        X509Certificate2 cert2 = cert.ToX509Certificate2();

        Assert.Equal(new DateTime(2021, 09, 30, 10, 1, 15), cert2.NotAfter);
        Assert.Equal(new DateTime(2000, 09, 30, 17, 12, 19), cert2.NotBefore);
        Assert.Equal("44AFB080D6A327BA893039862EF8406B", cert2.SerialNumber);

        X509ExtensionCollection extensions = cert2.Extensions;
        // This includes the ASN.1 DER tag and length of the actual value
        Assert.Equal("0414C4A7B1A47B2C71FADBE14B9075FFC41560858910", Convert.ToHexString(extensions["subjectKeyIdentifier"].RawData));

        Cert cert3 = Cert.FromX509Certificate2(cert2);
        Pem pem3 = cert3.ToPem();
        Assert.Equal(pem.ToData(), pem3.ToData());
    }
}
