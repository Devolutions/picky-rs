using System;
using System.IO;

using Xunit;

namespace Devolutions.Picky.Net48Tests;

// These tests run on .NET Framework 4.8, which the netstandard2.0 assembly also
// loads on. They don't re-test picky's crypto; they check that every *shape* of
// value crossing the FFI boundary marshals correctly under the legacy CLR. Each
// test is labelled with the marshalling shape it exercises.
public class FfiMarshallingTests
{
    // A real RSA key so we can exercise the RSA-only paths without paying for key generation.
    private const string RsaPrivateKeyPem = @"-----BEGIN PRIVATE KEY-----
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

    // Result<Box<T>, E> returning an opaque object: a by-value struct carrying
    // a pointer union and a discriminant.
    [Fact]
    public void ResultReturningObject_Ec()
    {
        using PrivateKey key = PrivateKey.GenerateEc(EcCurve.NistP256);
        Assert.Equal(KeyKind.Ec, key.Kind);
    }

    [Fact]
    public void ResultReturningObject_Ed()
    {
        using PrivateKey key = PrivateKey.GenerateEd(EdAlgorithm.Ed25519, false);
        Assert.Equal(KeyKind.Ed, key.Kind);
    }

    [Fact]
    public void ResultReturningObject_FromPem_Rsa()
    {
        using Pem pem = Pem.Parse(RsaPrivateKeyPem);
        using PrivateKey key = PrivateKey.FromPem(pem);
        Assert.Equal(KeyKind.Rsa, key.Kind);

        using PublicKey pub = key.ToPublicKey();
        Assert.Equal(KeyKind.Rsa, pub.Kind);
    }

    // Result<(), E> — the void-success arm.
    [Fact]
    public void ResultReturningVoid_SignatureVerifyFailsCleanly()
    {
        using Pem pem = Pem.Parse(RsaPrivateKeyPem);
        using PrivateKey priv = PrivateKey.FromPem(pem);
        using PublicKey pub = priv.ToPublicKey();
        using SignatureAlgorithm alg = SignatureAlgorithm.NewRsaPkcs1v15(HashAlgorithm.Sha2256);

        // A bogus signature must surface as a PickyException, not a crash.
        Assert.Throws<PickyException>(() =>
            alg.Verify(pub, new byte[] { 1, 2, 3 }, new byte[] { 9, 9, 9 }));
    }

    // Result<primitive, E> — a scalar success arm (long).
    [Fact]
    public void ResultReturningPrimitive_UtcDateTimestamp()
    {
        using UtcDate date = UtcDate.FromTimestamp(1_600_000_000);
        Assert.Equal(1_600_000_000, date.Timestamp);
    }

    // Result<String, E> via a DiplomatWrite out-param — the string-return shape.
    [Fact]
    public void ResultReturningString_PemRoundTrip()
    {
        byte[] payload = { 0xDE, 0xAD, 0xBE, 0xEF };
        using Pem pem = Pem.New("TEST DATA", payload);

        string repr = pem.ToRepr();
        Assert.Contains("TEST DATA", repr);

        Assert.Equal("TEST DATA", pem.Label);
    }

    // Hand-written addon returning byte[] (Pem.ToData / PublicKey.ToPkcs1).
    [Fact]
    public void AddonReturningByteArray_RoundTrip()
    {
        byte[] payload = { 1, 2, 3, 4, 5 };
        using Pem pem = Pem.New("BLOB", payload);
        Assert.Equal(payload, pem.ToData());
        Assert.Equal((ulong)payload.Length, pem.DataLength);
    }

    [Fact]
    public void AddonReturningByteArray_Pkcs1()
    {
        using Pem pem = Pem.Parse(RsaPrivateKeyPem);
        using PrivateKey priv = PrivateKey.FromPem(pem);
        using PublicKey pub = priv.ToPublicKey();
        byte[] pkcs1 = pub.ToPkcs1();
        Assert.NotEmpty(pkcs1);
    }

    // Option<Box<T>> — nullable opaque return.
    [Fact]
    public void OptionReturningObject_UtcDateYmd()
    {
        UtcDate? valid = UtcDate.Ymd(2020, 1, 1);
        Assert.NotNull(valid);
        using (valid)
        {
            Assert.Equal((ushort)2020, valid!.Year);
        }

        UtcDate? invalid = UtcDate.Ymd(2020, 13, 40);
        Assert.Null(invalid);
    }

    // Enum passed in by value; the encoded header shows the native side read the right member.
    [Fact]
    public void EnumByValue_JwsAlgReachesHeader()
    {
        using PrivateKey priv = PrivateKey.GenerateEc(EcCurve.NistP384);

        using JwtSigBuilder builder = JwtSig.Builder();
        builder.Algorithm = JwsAlg.Es384;
        builder.Claims = "{}";

        using JwtSig signed = builder.Build();
        using JwtSig decoded = JwtSig.DecodeUnchecked(signed.Encode(priv));
        Assert.Contains("ES384", decoded.Header);
    }

    // Result<String> through a longer pipeline (Argon2 password hashing).
    [Fact]
    public void ResultReturningString_Argon2()
    {
        using Argon2Params parameters = Argon2Params.New();
        parameters.MCost = 8;
        parameters.TCost = 1;
        parameters.PCost = 1;
        parameters.OutputLen = 32;

        using Argon2 argon2 = Argon2.New(Argon2Algorithm.Argon2id, parameters);
        string hash = argon2.HashPassword("correct horse battery staple");
        Assert.StartsWith("$argon2", hash);
    }

    // Full JWT encode/decode: builder property setters, string returns,
    // and object Results all in one flow.
    [Fact]
    public void JwtEncodeDecodeRoundTrip()
    {
        const string claims = "{\"sub\":\"net48\",\"admin\":true}";

        using PrivateKey priv = PrivateKey.GenerateEc(EcCurve.NistP256);

        using JwtSigBuilder builder = JwtSig.Builder();
        builder.Algorithm = JwsAlg.Es256;
        builder.ContentType = "AUTH";
        builder.Claims = claims;

        using JwtSig signed = builder.Build();
        string compact = signed.Encode(priv);
        Assert.False(string.IsNullOrEmpty(compact));

        using JwtSig decoded = JwtSig.DecodeUnchecked(compact);
        Assert.Equal("AUTH", decoded.ContentType);
        Assert.Contains("net48", decoded.Claims);
    }

    // VecU8: FromBytes, a value-return property, and Fill into a caller buffer
    // (Result<(), Box<BufferTooSmallError>> — the buffer-too-small error path).
    [Fact]
    public void VecU8_FillAndLength()
    {
        byte[] source = { 10, 20, 30, 40 };
        using VecU8 vec = VecU8.FromBytes(source);
        Assert.Equal((ulong)source.Length, (ulong)vec.Length);

        byte[] buffer = new byte[source.Length];
        vec.Fill(buffer);
        Assert.Equal(source, buffer);

        Assert.Throws<BufferTooSmallException>(() => vec.Fill(new byte[1]));
    }

    // The error arm: a bad parse must come back as a typed PickyException whose
    // payload (an opaque PickyError) is itself readable across the boundary.
    [Fact]
    public void ErrorArm_CarriesReadablePickyError()
    {
        PickyException ex = Assert.Throws<PickyException>(() => Pem.Parse("not a pem at all"));
        Assert.NotNull(ex.Inner);
        Assert.False(string.IsNullOrEmpty(ex.Inner.ToDisplay()));
        Assert.True(Enum.IsDefined(typeof(PickyErrorKind), ex.Inner.Kind));
    }

    // The tests below follow what the Devolutions Gateway PowerShell module does on
    // Windows PowerShell 5.1, the one shipping consumer that loads these bindings on
    // .NET Framework (powershell/DevolutionsGateway/Private/CertificateHelper.ps1).

    // Iterator returning Option<Box<T>> until null, plus nullable opaque getters:
    // Get-PemCertificate walking a password-protected PFX exported by certmgr.
    [Fact]
    public void Iterator_PfxSafeBags()
    {
        byte[] pfxBytes = File.ReadAllBytes(Asset("certmgr_aes256.pfx"));
        using Pkcs12CryptoContext cryptoContext = Pkcs12CryptoContext.WithPassword("test");
        using Pkcs12ParsingParams parsingParams = Pkcs12ParsingParams.New();
        using Pfx pfx = Pfx.FromDer(pfxBytes, cryptoContext, parsingParams);

        int certCount = 0;
        int keyCount = 0;

        using SafeBagIterator safeBags = pfx.SafeBags();
        SafeBag? safeBag;
        while ((safeBag = safeBags.Next()) is not null)
        {
            using (safeBag)
            {
                switch (safeBag.Kind)
                {
                    case SafeBagKind.Certificate:
                        {
                            using Cert? cert = safeBag.Certificate;
                            Assert.NotNull(cert);
                            using Pem pem = cert!.ToPem();
                            Assert.Contains("BEGIN CERTIFICATE", pem.ToRepr());
                            certCount++;
                            break;
                        }
                    case SafeBagKind.PrivateKey:
                        {
                            using PrivateKey? key = safeBag.PrivateKey;
                            Assert.NotNull(key);
                            using Pem pem = key!.ToPem();
                            Assert.Contains("PRIVATE KEY", pem.ToRepr());
                            keyCount++;
                            break;
                        }
                }
            }
        }

        Assert.NotEqual(0, certCount);
        Assert.Equal(1, keyCount);
    }

    // Byte-slice inputs: Get-PemCertificate with a DER certificate and a PKCS#8 key file.
    [Fact]
    public void SliceInput_DerCertAndPkcs8Key()
    {
        using Cert cert = Cert.FromDer(File.ReadAllBytes(Asset("asset_leaf.crt")));
        using Pem certPem = cert.ToPem();
        Assert.Contains("BEGIN CERTIFICATE", certPem.ToRepr());

        using Pem keyPem = Pem.Parse(RsaPrivateKeyPem);
        using PrivateKey key = PrivateKey.FromPkcs8(keyPem.ToData());
        Assert.Equal(KeyKind.Rsa, key.Kind);
    }

    // usize parameter (nuint): New-RsaKeyPair with the module's default key size.
    [Fact]
    public void UsizeParam_GenerateRsa()
    {
        using PrivateKey key = PrivateKey.GenerateRsa(2048);
        Assert.Equal(KeyKind.Rsa, key.Kind);

        using PublicKey pub = key.ToPublicKey();
        using Pem pem = pub.ToPem();
        Assert.Contains("PUBLIC KEY", pem.ToRepr());
    }

    private static string Asset(string name) => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, name);
}
