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

    private static readonly string privKeyPemRepr = @"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDkrPiL/5dmGIT5
/KuC3H/jIjeLoLoddsLhAlikO5JQQo3Zs71GwT4Wd2z8WLMe0lVZu/Jr2S28p0M8
F3Lnz4IgzjocQomFgucFWWQRyD03ZE2BHfEeelFsp+/4GZaM6lKZauYlIMtjR1vD
lflgvxNTr0iaii4JR9K3IKCunCRy1HQYPcZ9waNtlG5xXtW9Uf1tLWPJpP/3I5HL
M85JPBv4r286vpeUlfQIa/NB4g5w6KZ6MfEAIU4KeEQpeLAyyYvwUzPR2uQZ4y4I
4Nj84dWYB1cMTlSGugvSgOFKYit1nwLGeA7EevVYPbILRfSMBU/+avGNJJ8HCaaq
FIyY42W9AgMBAAECggEBAImsGXcvydaNrIFUvW1rkxML5qUJfwN+HJWa9ALsWoo3
h28p5ypR7S9ZdyP1wuErgHcl0C1d80tA6BmlhGhLZeyaPCIHbQQUa0GtL7IE+9X9
bSvu+tt+iMcB1FdqEFmGOXRkB2sS82Ax9e0qvZihcOFRBkUEK/MqapIV8qctGkSG
wIE6yn5LHRls/fJU8BJeeqJmYpuWljipwTkp9hQ7SdRYFLNjwjlz/b0hjmgFs5QZ
LUNMyTHdHtXQHNsf/GayRUAKf5wzN/jru+nK6lMob2Ehfx9/RAfgaDHzy5BNFMj0
i9+sAycgIW1HpTuDvSEs3qP26NeQ82GbJzATmdAKa4ECgYEA9Vti0YG+eXJI3vdS
uXInU0i1SY4aEG397OlGMwh0yQnp2KGruLZGkTvqxG/Adj1ObDyjFH9XUhMrd0za
Nk/VJFybWafljUPcrfyPAVLQLjsBfMg3Y34sTF6QjUnhg49X2jfvy9QpC5altCtA
46/KVAGREnQJ3wMjfGGIFP8BUZsCgYEA7phYE/cYyWg7a/o8eKOFGqs11ojSqG3y
0OE7kvW2ugUuy3ex+kr19Q/8pOWEc7M1UEV8gmc11xgB70EhIFt9Jq379H0X4ahS
+mgLiPzKAdNCRPpkxwwN9HxFDgGWoYcgMplhoAmg9lWSDuE1Exy8iu5inMWuF4MT
/jG+cLnUZ4cCgYAfMIXIUjDvaUrAJTp73noHSUfaWNkRW5oa4rCMzjdiUwNKCYs1
yN4BmldGr1oM7dApTDAC7AkiotM0sC1RGCblH2yUIha5NXY5G9Dl/yv9pHyU6zK3
UBO7hY3kmA611aP6VoACLi8ljPn1hEYUa4VR1n0llmCm29RH/HH7EUuOnwKBgExH
OCFp5eq+AAFNRvfqjysvgU7M/0wJmo9c8obRN1HRRlyWL7gtLuTh74toNSgoKus2
y8+E35mce0HaOJT3qtMq3FoVhAUIoz6a9NUevBZJS+5xfraEDBIViJ4ps9aANLL4
hlV7vpICWWeYaDdsAHsKK0yjhjzOEx45GQFA578RAoGBAOB42BG53tL0G9pPeJPt
S2LM6vQKeYx+gXTk6F335UTiiC8t0CgNNQUkW105P/SdpCTTKojAsOPMKOF7z4mL
lj/bWmNq7xu9uVOcBKrboVFGO/n6FXyWZxHPOTdjTkpe8kvvmSwl2iaTNllvSr46
Z/fDKMxHxeXla54kfV+HiGkH
-----END PRIVATE KEY-----";

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

        Assert.Equal(new DateTime(2000, 09, 30, 21, 12, 19, DateTimeKind.Utc), cert2.NotBefore.ToUniversalTime());
        Assert.Equal(new DateTime(2021, 09, 30, 14, 1, 15, DateTimeKind.Utc), cert2.NotAfter.ToUniversalTime());
        Assert.Equal("44AFB080D6A327BA893039862EF8406B", cert2.SerialNumber);

        X509ExtensionCollection extensions = cert2.Extensions;
        X509Extension? skiExt = extensions["subjectKeyIdentifier"];
        Assert.NotNull(skiExt);
        byte[] skiExtRawData = skiExt!.RawData; // includes the ASN.1 DER tag and length of the actual value
        Assert.Equal("0414C4A7B1A47B2C71FADBE14B9075FFC41560858910", Convert.ToHexString(skiExtRawData));

        Cert cert3 = Cert.FromX509Certificate2(cert2);
        Pem pem3 = cert3.ToPem();
        Assert.Equal(pem.ToData(), pem3.ToData());
    }

    [Fact]
    public void GenerateSelfSignedCertSmoke()
    {
        Pem pem = Pem.Parse(privKeyPemRepr);
        PrivateKey priv = PrivateKey.FromPem(pem);

        CertificateBuilder builder = CertificateBuilder.New();
        builder.ValidFrom = UtcDate.New(2000, 09, 30, 17, 12, 19);
        builder.ValidTo = UtcDate.New(2021, 09, 30, 10, 1, 15);
        builder.SubjectDnsName = "devolutions.net";
        builder.IssuerCommonName = "devolutions.net";
        builder.IssuerKey = priv;
        builder.KpServerAuth = true;
        builder.KuDigitalSignature = true;
        builder.SelfSigned = true;
        Cert cert = builder.Build();
        
        X509Certificate2 cert2 = cert.ToX509Certificate2();

        Assert.Equal(new DateTime(2000, 09, 30, 17, 12, 19, DateTimeKind.Utc), cert2.NotBefore.ToUniversalTime());
        Assert.Equal(new DateTime(2021, 09, 30, 10, 1, 15, DateTimeKind.Utc), cert2.NotAfter.ToUniversalTime());
    }
}
