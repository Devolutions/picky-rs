using System;
using System.Text.Json;

using Xunit;

namespace Devolutions.Picky.Tests;

public class JwtTests
{
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

    private static readonly string pubKeyPemRepr = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5Kz4i/+XZhiE+fyrgtx/
4yI3i6C6HXbC4QJYpDuSUEKN2bO9RsE+Fnds/FizHtJVWbvya9ktvKdDPBdy58+C
IM46HEKJhYLnBVlkEcg9N2RNgR3xHnpRbKfv+BmWjOpSmWrmJSDLY0dbw5X5YL8T
U69ImoouCUfStyCgrpwkctR0GD3GfcGjbZRucV7VvVH9bS1jyaT/9yORyzPOSTwb
+K9vOr6XlJX0CGvzQeIOcOimejHxACFOCnhEKXiwMsmL8FMz0drkGeMuCODY/OHV
mAdXDE5UhroL0oDhSmIrdZ8CxngOxHr1WD2yC0X0jAVP/mrxjSSfBwmmqhSMmONl
vQIDAQAB
-----END PUBLIC KEY-----";

    private static readonly string claims = @"{""admin"":true,""exp"":1516539022,""iat"":1516239022,""name"":""John Doe"",""nbf"":1516239022}";

    private static readonly string headerSection = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFVVEgiLCJraWQiOiJtYXN0ZXIta2V5In0";

    private static readonly string payloadSection = "eyJhZG1pbiI6dHJ1ZSwiZXhwIjoxNTE2NTM5MDIyLCJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsIm5iZiI6MTUxNjIzOTAyMn0";

    private static readonly string signedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFVVEgiLCJraWQiOiJtYXN0ZXIta2V5In0.eyJhZG1pbiI6dHJ1ZSwiZXhwIjoxNTE2NTM5MDIyLCJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsIm5iZiI6MTUxNjIzOTAyMn0.wqZcddQCA2UZj8-pT5GRj1GCTJWwVlE6uHgjMq18vctvmzNVYD34ri4-61qW460J64JmG5ZYwqOedNSlSqCl3lY63BkXrSRYOKnwWJTwoljz3BrLKx4t6jeBTJVMFLs7JiiCoxNc2uq33qh8F08cV_2fjALvgBdm3pkFgm-y-P07fBYLnXcuP5-OOMvynQmoqXd2zm-XH1YbwTW_8LYoJH_Aqfgyqfrcs1BEzJEGJUtL-HPictnswutW9c1dvwgI5Tr7PdltTu7hRuJof7ojZYDADg_aaecjzsI1zXu0NU_-DwAzrPaR5QTaDTTNyJRPwDjr7l0Dtdq5USMt48bSNg";

    [Fact]
    public void Smoke()
    {
        JwtSigBuilder builder = JwtSig.Builder();
        builder.Kid = "master-key";
        builder.ContentType = "AUTH";
        builder.Claims = claims;

        JwtSig jwt = builder.Build();
        Assert.Equal("master-key", jwt.Kid);
        Assert.Equal("AUTH", jwt.ContentType);
        Assert.Equal(claims, jwt.Claims);

        Pem pem = Pem.Parse(privKeyPemRepr);
        PrivateKey priv = PrivateKey.FromPem(pem);
        string encoded = jwt.Encode(priv);
        string[] parts = encoded.Split('.');
        Assert.Equal(headerSection, parts[0]);
        Assert.Equal(payloadSection, parts[1]);
    }

    [Fact]
    public void DecodeSignedJwt()
    {
        Pem pem = Pem.Parse(pubKeyPemRepr);
        PublicKey key = PublicKey.FromPem(pem);
        JwtValidator validator = JwtValidator.Strict(1516259022, 0);
        JwtSig jwt = JwtSig.Decode(signedJwt, key, validator);
        Assert.Equal("master-key", jwt.Kid);
        Assert.Equal("AUTH", jwt.ContentType);
        Assert.Equal(claims, jwt.Claims);
    }

    [Fact]
    public void DecodeExpired()
    {
        Pem pem = Pem.Parse(pubKeyPemRepr);
        PublicKey key = PublicKey.FromPem(pem);
        JwtValidator validator = JwtValidator.Strict(1516639022, 0);

        try {
            JwtSig jwt = JwtSig.Decode(signedJwt, key, validator);
            Assert.True(false, "Expected a PickyException thrown");
        } catch (PickyException e) {
            Assert.Equal(PickyErrorKind.Expired, e.Inner.Kind);
        }
    }

    [Fact]
    public void AdditionalHeaderParameters()
    {
        string additionalObject = @"{""answer"":42,""foo"":""bar""}";

        JwtSigBuilder builder = JwtSig.Builder();
        builder.Algorithm = JwsAlg.RS512;
        builder.Claims = claims;
        builder.AddAdditionalParameterString("additional_token", "abcd.efgh.ijklm");
        builder.AddAdditionalParameterObject("additional_object", additionalObject);
        builder.AddAdditionalParameterPosInt("additional_number", 64);
        builder.AddAdditionalParameterNegInt("additional_negative_number", -64);

        JwtSig jwt = builder.Build();

        {
            Assert.Equal(claims, jwt.Claims);

            JsonElement header = JsonDocument.Parse(jwt.Header).RootElement;
            Assert.Equal("RS512", header.GetProperty("alg").GetString());
            Assert.Equal("JWT", header.GetProperty("typ").GetString());
            Assert.Equal("abcd.efgh.ijklm", header.GetProperty("additional_token").GetString());
            Assert.Equal(42, header.GetProperty("additional_object").GetProperty("answer").GetInt32());
            Assert.Equal("bar", header.GetProperty("additional_object").GetProperty("foo").GetString());
            Assert.Equal((ulong)64, header.GetProperty("additional_number").GetUInt64());
            Assert.Equal(-64, header.GetProperty("additional_negative_number").GetInt64());
        }

        Pem pem = Pem.Parse(privKeyPemRepr);
        PrivateKey priv = PrivateKey.FromPem(pem);
        string encoded = jwt.Encode(priv);

        {
            string[] parts = encoded.Split('.');
            Assert.Equal(payloadSection, parts[1]);

            // Decode header part (url-safe base64-encoded)
            byte[] headerPartBytes = Convert.FromBase64String(parts[0].Replace('-', '+').Replace('_', '/') + "==");
            string headerPart = System.Text.Encoding.UTF8.GetString(headerPartBytes);

            JsonElement header = JsonDocument.Parse(headerPart).RootElement;
            Assert.Equal("RS512", header.GetProperty("alg").GetString());
            Assert.Equal("JWT", header.GetProperty("typ").GetString());
            Assert.Equal("abcd.efgh.ijklm", header.GetProperty("additional_token").GetString());
            Assert.Equal(42, header.GetProperty("additional_object").GetProperty("answer").GetInt32());
            Assert.Equal("bar", header.GetProperty("additional_object").GetProperty("foo").GetString());
            Assert.Equal((ulong)64, header.GetProperty("additional_number").GetUInt64());
            Assert.Equal(-64, header.GetProperty("additional_negative_number").GetInt64());
        }
    }
}
