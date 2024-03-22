using System;
using Devolutions.Picky.Diplomat;
using Xunit;

namespace Devolutions.Picky.Tests;

public class Pkcs7Tests
{

    static readonly string pkcs7_pem = @"-----BEGIN PKCS7-----
MIIKvwYJKoZIhvcNAQcCoIIKsDCCCqwCAQExADALBgkqhkiG9w0BBwGgggqSMIID
QjCCAioCAQMwDQYJKoZIhvcNAQELBQAwYTELMAkGA1UEBhMCSW4xCzAJBgNVBAgM
AkluMQswCQYDVQQHDAJJbjELMAkGA1UECgwCSW4xCzAJBgNVBAsMAkluMQswCQYD
VQQDDAJJbjERMA8GCSqGSIb3DQEJARYCSW4wHhcNMjEwNzA4MTE1NjQ5WhcNMjIw
NzA4MTE1NjQ5WjBtMQswCQYDVQQGEwJMZjENMAsGA1UECAwETGVhZjENMAsGA1UE
BwwETGVhZjENMAsGA1UECgwETGVhZjENMAsGA1UECwwETGVhZjENMAsGA1UEAwwE
TGVhZjETMBEGCSqGSIb3DQEJARYETGVhZjCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBANdMZ/MHsDoW4K1G3TB8z0TDbKQeBTYv7//rlPv81OMLhkMJgcQb
XkhHkSoyynw/wUAvWH3U8ZN4vYc4jWuw/j4pTjsf2lf1MQFoVZJehaqYoTfsYaIi
89AwHxDlkQitumuWs24VrPCe2PO+fNM04V/4FgI1RniOsAFTlSfNyG2cIZCYbAVk
pBCmci5LbAlm2zC6zZBoGpp1GqjFnwR7JJQcgOKHr9inJmjFM0D0ZIiadDKHSuKm
U9c6vdAQHWrIXHaxvZspLg2YUWH9dDZVe+ddSuGEM7772N9/FdaMe+7r/r5uim4E
imhdjn+PPa3Qhr6eD3nkNd+s3wtVekyYQIUCAwEAATANBgkqhkiG9w0BAQsFAAOC
AQEAT0Bzl3U+fxhAEAGgU1gp0og7J9VM1diprUOl3C1RHUZtovlTBctltqDdSc7o
YY4r3ubo25mkvJ0PH8d3pGJDOvE9SnmgP4BRschCu2LOjXgbV3pBk6ejgvPPTcMo
rwiNJxf5exX35Ju1AzcpI71twP9Ty8YBOg3aAhqwu8MdcXbXbPESg5X8wpb30qVi
RH7PzyAJlQynqCWMxTECXgtwLISHp/Ae2x3MUT2CKBZC65Z17UdYHN7uR0zavKwb
3A2jzIPySFJL/KSy9WZLwmQdMUU3tcFRHDpaoMmJpPNBBbcXuhFoP9MLWTmm9+ma
yaK7vOyltAK3MVuCpmccl7SNjDCCA5wwggKEoAMCAQICAQIwDQYJKoZIhvcNAQEL
BQAwbTELMAkGA1UEBhMCUnQxDTALBgNVBAgMBFJvb3QxDTALBgNVBAcMBFJvb3Qx
DTALBgNVBAoMBFJvb3QxDTALBgNVBAsMBFJvb3QxDTALBgNVBAMMBFJvb3QxEzAR
BgkqhkiG9w0BCQEWBFJvb3QwHhcNMjEwNzA4MDkwMzMxWhcNMjIwNzA4MDkwMzMx
WjBhMQswCQYDVQQGEwJJbjELMAkGA1UECAwCSW4xCzAJBgNVBAcMAkluMQswCQYD
VQQKDAJJbjELMAkGA1UECwwCSW4xCzAJBgNVBAMMAkluMREwDwYJKoZIhvcNAQkB
FgJJbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN4llgeaEesdTv+L
mWhrMmluN1LnveWuQsRBV7dySd1d/3gRWwFMxXfaBjh1y/mDhGe1Kb8zz0buSOyn
WMhT3xppsumF9y6aOGupSUij+nC+VFkcbZzWxJKBRJGJWcmPMNm+eEumY0ZrS21e
EvVmKPlZSCZUkJgx3ogEsKaUQrHymx9+AUvjGGsIbmOB07cEcVjxz3eexOr7cMVw
XXdnujdsgLYiR5rkxTP4pKkB4CdPEfy+q6cwO5KtO5pkgMcIhHCC/P+9pfwS5CVF
5mUb0xj+yZGQ85fezRKy7mGSMhRvNvIhmnoVWyuvkoYdFUWzEDZqj4YJpJMHT2RN
hTIdx0cCAwEAAaNTMFEwHQYDVR0OBBYEFHmBQGjcx/fnNFj4UxGyeCHFb/aaMB8G
A1UdIwQYMBaAFEcLWYRko86McWZbVwnLHJXW/B1SMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBAI3oKESkfFQ/0B3xLFYvXMCuWv224wxGdw0TWi64
8OwmCrNgYEXmkQPz4SZ0oQJjazllAflF+5Kc49zSdrCOPPz6bhw9O4Pcn875jCYl
CD23+OexKGyfXFgc7/bzKTjN2tXA/Slo9ol1xvvY9HnhpL2UFf0jkecz41rP+TRl
sxG7LwEF24P3xgZLlaySCp2S9WcBtIf7p1Z+6ekLl4KwihD/Q4uhibhFQqqOPuj8
Fc4Jy8eyZ+0vEoVTQMrFahUrKjbfuxtYZ+8y5S4QbL6O5Ox7mYmTrloDUd0UIzMF
iprHKnwHFjVAYDJkq6t5xt1o2kJ0EVSZkyUaD4U/zoSNHBIwggOoMIICkKADAgEC
AgEBMA0GCSqGSIb3DQEBCwUAMG0xCzAJBgNVBAYTAlJ0MQ0wCwYDVQQIDARSb290
MQ0wCwYDVQQHDARSb290MQ0wCwYDVQQKDARSb290MQ0wCwYDVQQLDARSb290MQ0w
CwYDVQQDDARSb290MRMwEQYJKoZIhvcNAQkBFgRSb290MB4XDTIxMDcwODA5MDI1
M1oXDTIyMDcwODA5MDI1M1owbTELMAkGA1UEBhMCUnQxDTALBgNVBAgMBFJvb3Qx
DTALBgNVBAcMBFJvb3QxDTALBgNVBAoMBFJvb3QxDTALBgNVBAsMBFJvb3QxDTAL
BgNVBAMMBFJvb3QxEzARBgkqhkiG9w0BCQEWBFJvb3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC8dV0AD30BbZdBr9laj5sKb+PIzW2P/gir7VXXCz+q
UHoZvK6ZqDW1K+jn4iTEx+HUGH9JYhB3syYOrMpi7CjXjz2x0lVJKvx5qSieGrQr
yJaWePwhDWfVUjHVfbcFfdJLAH3pZjfNKHmm68n37Acc/mFZXTG3xN0yfQgbPwbO
NGcfUze1u2kcpVjHJ1yOk9wwdO252HhJJx1Hd5wKWgeTkBQ73/vtZCQuLN3MZ+d4
ModaTtCj/dA88p4PMyw2POiCpFrgxPxVrjfjPb6V7HmNP/1xzFEFkJvTfWlTmlCX
rYG8BL3jHqfVw5gM1o1f1nClOpX/fmjqHvzT1AZ17IGVAgMBAAGjUzBRMB0GA1Ud
DgQWBBRHC1mEZKPOjHFmW1cJyxyV1vwdUjAfBgNVHSMEGDAWgBRHC1mEZKPOjHFm
W1cJyxyV1vwdUjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCL
KgLbBc2R5oB0al9ce68zIRpdyoNVR2TTTqwzD5K0m4HhI93dG+1e4Mbtr970Q8DM
KQvjvT0nf/jJjjoUKVG0dszTNPg5qlHPL+OgAj44dHzf7jBgEGJAez3Pk4zC4zvi
0BusfObVryc0j3oZ2JFIRaBdon4MPI2HcTMLzPFMcprzMnDx7aQbDlkQLksL1Z2E
5VvopUG5rTMMWItwWAVHwT/J9x0MPYs+LFc3Yeg7l3hsV03gC1jsh6pd0MR3p5vr
WrOnUvpo7YFFGlKamwRpxIlYAgSEQFnD3LOjx+NGdGP1H0PQd9DA4xCwtPKkoCSw
bOrBNDoLzSPaN6jy3JNeoQAxAA==
-----END PKCS7-----";

    static readonly string private_key = @"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXTGfzB7A6FuCt
Rt0wfM9Ew2ykHgU2L+//65T7/NTjC4ZDCYHEG15IR5EqMsp8P8FAL1h91PGTeL2H
OI1rsP4+KU47H9pX9TEBaFWSXoWqmKE37GGiIvPQMB8Q5ZEIrbprlrNuFazwntjz
vnzTNOFf+BYCNUZ4jrABU5UnzchtnCGQmGwFZKQQpnIuS2wJZtswus2QaBqadRqo
xZ8EeySUHIDih6/YpyZoxTNA9GSImnQyh0riplPXOr3QEB1qyFx2sb2bKS4NmFFh
/XQ2VXvnXUrhhDO++9jffxXWjHvu6/6+bopuBIpoXY5/jz2t0Ia+ng955DXfrN8L
VXpMmECFAgMBAAECggEAWa5fAnHqa1gKQMNq8X6by9XnlDlZDGhNfXoBNjHr76Nm
SthT8H9B97Ov+Tbs93KLKhROtSOVeUtrDz90US6JyRTlnGU5Szg8MIzoUC8FWLl5
NlVFmgcbLlZNKnmlv0q2g4hjt3BZ+GUClA1963B0jMhHSqYsc51kHTlWwRzL5zPF
ekddpixpkE8fogE5+OTRtTlU6grWM0cMN/pNZK03A9H7APzUDZMxr51ues+cC2MH
OLiw2mjRgXCjK+IXutcCJToicp1JRWAuA0WjMTzjfMXUfm25bwcCMmyznMJiDTU2
JJ1OVYzTgQbsyftFs8E+05L5n2E/bAAH3/9OOFMxoQKBgQDvy6NLjoCk9OR1EQf5
0aCvUH3ZtGk/JBtM61F81Z6he0bSOFwKKGH8cv9f4TLqpIZWRoaD+SCWBTs+9iCp
kQHdfTe7/ElmUloxQRQVA7UXeoPA/JgX021YQFjLASNnBHSP5hMDnMGbDox9uuSn
1MEPzP5gljnECHko/rDh+Ab2SQKBgQDl2PrxDjBS0z5TymKgg5zsRFzanuJDOYjW
VGju4zmduqof9Mo2loRR33/xUu0jxrKhdHUx5pJRU/rlDaG7/lKNE4ZoF6RMh//C
traUCFLB55TMUEaAWPiBTVvbZRg4W5iIYc+HRz1uBnk+5c5rlShPVZwlXO3fKaom
3K8dXWqIXQKBgQDDpZNrDy6Y6BIKDcZDJq0CvRqhaJhCYxQ/MvP+dVCDElDbLg6y
XvZrgewob1YaqffNJqeTv8y9ejE3kptdnik2bHbv0syURna+Hwnih27WZChhafYx
4lghnAaWQyx+Xd04lxBGbzxrZXhtEPKEmIqYeLnHVmp1LjCkqQDqrXIIuQKBgHVe
ubYCotaInJk5DegdjTJxLmFNJQljBec8r2Ddk3xh56Ht5Jy/e847LSBUUlgkjO85
gub6cNkq40G4FlDja9Aymj3pZLLX99i8aLtrDKeL1EYI8Bd2V1/f2vpLw3R0AY4T
NGBGFq5qi9t8ik4RmsX4V4YU0DtXEVZK9vktzMrZAoGAHy698y0i0L4AIGlpIuW7
YZcLE0RSUfCdPA8HQad98GSKP8aipONwLbVT9KmTEmUA02g0Nb2caFirW3OYKZ8l
qOuqrRK+/evcuQixBSTPbAdNWyhbwYgSLUtR6q8erOmfdjjt5MD9SoS/luDV89NF
ocqmQTrEqWzH7mmVUFXY5GA=
-----END PRIVATE KEY-----";

    [Fact]
    public void Parse()
    {
        Pem pem = Pem.Parse(pkcs7_pem);
        Pkcs7 pkcs7 = Pkcs7.FromPem(pem);

        Pem newPem = pkcs7.ToPem();

        Assert.Equal(pem.ToRepr(), newPem.ToRepr());
    }

    [Fact]
    public void SelfSignedAuthenticodeSignatureBasicValidation()
    {
        Pem pem = Pem.Parse(pkcs7_pem);
        Pkcs7 pkcs7 = Pkcs7.FromPem(pem);

        byte[] FILE_HASH = [
            0xa7, 0x38, 0xda, 0x44, 0x46, 0xa4, 0xe7, 0x8a, 0xb6, 0x47, 0xdb, 0x7e, 0x53, 0x42, 0x7e, 0xb0, 0x79, 0x61,
            0xc9, 0x94, 0x31, 0x7f, 0x4c, 0x59, 0xd7, 0xed, 0xbe, 0xa5, 0xcc, 0x78, 0x6d, 0x80,
        ];

        VecU8 fileHashBuffer = VecU8.FromBytes(FILE_HASH);
        RsString program_name = RsString.FromString("decoding_into_authenticode_signature");
        PrivateKey privateKey = PrivateKey.FromPemStr(private_key);

        AuthenticodeSignature signature = AuthenticodeSignature.New(pkcs7, fileHashBuffer, ShaVariant.SHA2_256, privateKey, program_name);
        Assert.NotNull(signature);

        VecU8? file_hash = signature?.FileHash();

        Assert.NotNull(file_hash);

        AuthenticodeValidator? validator = signature?.AuthenticodeVerifier();

        Assert.NotNull(validator);

        if (null == validator)
        {
            return;
        }

        validator.RequireBasicAuthenticodeValidation(fileHashBuffer);
        validator.IgnoreChainCheck();
        validator.IgnoreSigningCertificateCheck();
        validator.IgnoreNotAfterCheck();
        validator.IgnoreNotBeforeCheck();
        try
        {
            validator.Verify();

        }
        catch (PickyException e)
        {
            DiplomatWriteable writeable = new DiplomatWriteable();
            e.Inner.ToDisplay(writeable);
            string? error = writeable.ToUtf8Bytes()?.ToString();
            Console.WriteLine(error);
            Assert.True(false);
        }
    }

}