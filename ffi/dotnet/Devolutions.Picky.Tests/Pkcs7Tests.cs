using Xunit;

namespace Devolutions.Picky.Tests;

public class Pkcs7Tests
{

    private static readonly string p7bRepr = @"-----BEGIN PKCS7-----
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
zEFv26UMfItGCUWhADEA
-----END PKCS7-----
    ";

    private static readonly string private_key = @"-----BEGIN PRIVATE KEY-----
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
        Pem pem = Pem.Parse(p7bRepr);
        Pkcs7 pkcs7 = Pkcs7.FromPem(pem);

        Pem newPem = pkcs7.ToPem();

        Assert.Equal(pem.ToRepr(), newPem.ToRepr());
    }

    [Fact]
    public void SelfSignedAuthenticodeSignatureBasicValidation()
    {
        Pem pem = Pem.Parse(p7bRepr);
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
        validator.Verify();
    }

}