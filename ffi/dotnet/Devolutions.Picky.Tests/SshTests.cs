using System;

using Xunit;

namespace Devolutions.Picky.Tests;

public class SshTests
{
    private static readonly string privateKeyPemRepr = @"-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----";

    [Fact]
    public void PrivateKeyParse()
    {
        var pem = Pem.Parse(privateKeyPemRepr);
        var key = SshPrivateKey.FromPem(pem, "");
        Assert.Equal("test@picky.com", key.Comment);
        Assert.Equal("none", key.CipherName);
    }

    private static readonly string hostCertStrRepr = "ssh-rsa-cert-v01@openssh.com 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 sasha@kubuntu\r\n";

    [Fact]
    public void CertSmoke()
    {
        var cert = SshCert.Parse(hostCertStrRepr);
        Assert.Equal(SshCertType.Host, cert.CertType);
        Assert.Equal("picky", cert.KeyId);
        Assert.Equal("sasha@kubuntu", cert.Comment);
        Assert.Equal(hostCertStrRepr, cert.ToRepr());
    }

    [Fact]
    public void CertBuilder()
    {
        var privateKey = SshPrivateKey.FromPem(Pem.Parse(privateKeyPemRepr), "");
        ulong validAfter = 1000;
        ulong validBefore = 2000;

        var builder = SshCert.Builder();
        builder.CertKeyType = SshCertKeyType.RsaSha2_256V01;
        builder.Key = privateKey.ToPublicKey();
        builder.CertType = SshCertType.Host;
        builder.ValidAfter = validAfter;
        builder.ValidBefore = validBefore;
        builder.SignatureKey = privateKey;
        builder.Comment = "hello!";
        var cert = builder.Build();

        Assert.Equal(SshCertKeyType.RsaSha2_256V01, cert.SshKeyType);
        Assert.Equal(SshCertType.Host, cert.CertType);
        Assert.Equal((ulong)1000, cert.ValidAfter);
        Assert.Equal((ulong)2000, cert.ValidBefore);
        Assert.Equal("hello!", cert.Comment);
    }
}
