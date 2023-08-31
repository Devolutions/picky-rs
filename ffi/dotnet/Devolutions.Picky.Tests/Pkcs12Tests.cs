using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

using Xunit;

namespace Devolutions.Picky.Tests;

public class Pkcs12Tests
{
    static readonly string leafPrivateKey = "../../../../../../../test_assets/private_keys/rsa-2048-pk_3.key";
    static readonly string leafCertPath = "../../../../../../../test_assets/pkcs12/asset_leaf.crt";
    static readonly string intermediateCertPath = "../../../../../../../test_assets/pkcs12/asset_intermediate.crt";
    static readonly string rootCertPath = "../../../../../../../test_assets/pkcs12/asset_root.crt";
    static readonly string pfxSample = "../../../../../../../test_assets/pkcs12/openssl_nocrypt.pfx";
    static readonly string pfxSampleWithPassword = "../../../../../../../test_assets/pkcs12/certmgr_aes256.pfx";

    [Fact]
    public void PfxBuild()
    {
        Pkcs12CryptoContext cryptoContext = Pkcs12CryptoContext.WithPassword("test");

        byte[] leafBytes = File.ReadAllBytes(leafCertPath);
        Cert leaf = Cert.FromDer(leafBytes);
        SafeBag leafSafeBag = SafeBag.NewCertificate(leaf);
        leafSafeBag.AddAttribute(Pkcs12Attribute.NewFriendlyName("LEAF_CERT"));
        leafSafeBag.AddAttribute(Pkcs12Attribute.NewLocalKeyId(new byte[] { 0x01, 0x00, 0x00, 0x00 }));

        string leafKeyPemRepr = File.ReadAllText(leafPrivateKey);
        Pem leafKeyPem = Pem.Parse(leafKeyPemRepr);
        PrivateKey leafKey = PrivateKey.FromPem(leafKeyPem);
        SafeBag leafKeySafeBag = SafeBag.NewEncryptedKey(leafKey, cryptoContext);
        leafKeySafeBag.AddAttribute(Pkcs12Attribute.NewFriendlyName("LEAF_CERT"));
        leafKeySafeBag.AddAttribute(Pkcs12Attribute.NewLocalKeyId(new byte[] { 0x01, 0x00, 0x00, 0x00 }));

        byte[] intermediateBytes = File.ReadAllBytes(intermediateCertPath);
        Cert intermediate = Cert.FromDer(intermediateBytes);
        SafeBag intermediateSafeBag = SafeBag.NewCertificate(intermediate);
        intermediateSafeBag.AddAttribute(Pkcs12Attribute.NewFriendlyName("INTERMEDIATE_CERT"));

        byte[] rootBytes = File.ReadAllBytes(rootCertPath);
        Cert root = Cert.FromDer(rootBytes);
        SafeBag rootSafeBag = SafeBag.NewCertificate(root);
        rootSafeBag.AddAttribute(Pkcs12Attribute.NewFriendlyName("ROOT_CERT"));

        PfxBuilder builder = Pfx.Builder(cryptoContext);

        builder.AddSafeBagToCurrentSafeContents(leafSafeBag);
        builder.AddSafeBagToCurrentSafeContents(intermediateSafeBag);
        builder.AddSafeBagToCurrentSafeContents(rootSafeBag);
        builder.MarkEncryptedSafeContentsAsReady();

        builder.AddSafeBagToCurrentSafeContents(leafKeySafeBag);
        builder.MarkSafeContentsAsReady();

        Pfx pfx = builder.Build();

        // Ensure it’s possible to encode and decode the PFX using the same crypto context (~= same password)
        byte[] derRepr = pfx.ToDer();
        Pkcs12ParsingParams parsingParams = Pkcs12ParsingParams.New();
        Pfx pfxParsed = Pfx.FromDer(derRepr, cryptoContext, parsingParams);

        // Round-trip smoke test
        byte[] parsedDerRepr = pfxParsed.ToDer();
        Assert.Equal(derRepr, parsedDerRepr);
    }

    [Fact]
    public void ReadAndInspectPfx()
    {
        Pkcs12CryptoContext cryptoContext = Pkcs12CryptoContext.NoPassword();
        Pkcs12ParsingParams parsingParams = Pkcs12ParsingParams.New();

        byte[] pfxBytes = File.ReadAllBytes(pfxSample);
        Pfx pfx = Pfx.FromDer(pfxBytes, cryptoContext, parsingParams);

        int safeBagCount = 0;
        int privateKeyCount = 0;
        int certificateCount = 0;
        int myCertCount = 0;
        int secretCount = 0;
        int unknownCount = 0;
        int attrCount = 0;
        int friendlyNameCount = 0;
        int localKeyIdCount = 0;
        int customAttrCount = 0;

        SafeBagIterator safeBagIt = pfx.SafeBags();
        SafeBag? safeBag = safeBagIt.Next();

        while (safeBag is not null)
        {
            safeBagCount++;

            switch (safeBag.Kind)
            {
                case SafeBagKind.PrivateKey:
                    {
                        privateKeyCount++;
                        Assert.NotNull(safeBag.PrivateKey);
                        Assert.True(safeBag.ContainsFriendlyName("my_cert"));
                        Assert.True(safeBag.ContainsLocalKeyId(Convert.FromHexString("2A4D6C0CCDCBC90B195B68AE069DBC8922A97F40")));
                        break;
                    }
                case SafeBagKind.Certificate:
                    {
                        certificateCount++;

                        Assert.NotNull(safeBag.Certificate);

                        if (safeBag.ContainsFriendlyName("my_cert"))
                        {
                            myCertCount++;
                            Assert.True(safeBag.ContainsLocalKeyId(Convert.FromHexString("2A4D6C0CCDCBC90B195B68AE069DBC8922A97F40")));
                        }

                        break;
                    }
                case SafeBagKind.Secret:
                    {
                        secretCount++;
                        break;
                    }
                case SafeBagKind.Unknown:
                    {
                        unknownCount++;
                        break;
                    }
            }

            Pkcs12AttributeIterator attrIt = safeBag.Attributes();
            Pkcs12Attribute? attr = attrIt.Next();

            while (attr is not null)
            {
                attrCount++;

                switch (attr.Kind)
                {
                    case Pkcs12AttributeKind.FriendlyName:
                        {
                            friendlyNameCount++;
                            Assert.Equal("my_cert", attr.FriendlyName);
                            break;
                        }
                    case Pkcs12AttributeKind.LocalKeyId:
                        {
                            localKeyIdCount++;
                            break;
                        }
                    case Pkcs12AttributeKind.Custom:
                        {
                            customAttrCount++;
                            break;
                        }
                }

                attr = attrIt.Next();
            }

            safeBag = safeBagIt.Next();
        }

        Assert.Equal(4, safeBagCount);
        Assert.Equal(1, privateKeyCount);
        Assert.Equal(3, certificateCount);
        Assert.Equal(1, myCertCount);
        Assert.Equal(0, secretCount);
        Assert.Equal(0, unknownCount);
        Assert.Equal(4, attrCount);
        Assert.Equal(2, friendlyNameCount);
        Assert.Equal(2, localKeyIdCount);
        Assert.Equal(0, customAttrCount);
    }

    [Fact]
    public void ReadWithWrongPassword()
    {
        Pkcs12CryptoContext cryptoContext = Pkcs12CryptoContext.WithPassword("shenanigans");
        Pkcs12ParsingParams parsingParams = Pkcs12ParsingParams.New();

        byte[] pfxBytes = File.ReadAllBytes(pfxSampleWithPassword);

        try
        {
            Pfx.FromDer(pfxBytes, cryptoContext, parsingParams);
            Assert.True(false, "Expected a PickyException to be thrown");
        }
        catch (PickyException e)
        {
            Assert.Equal(PickyErrorKind.Pkcs12MacValidation, e.Inner.Kind);
        }
    }

    [Fact]
    public void ReadWithWrongPasswordLenient()
    {
        Pkcs12CryptoContext cryptoContext = Pkcs12CryptoContext.WithPassword("bumfuzzle");

        Pkcs12ParsingParams parsingParams = Pkcs12ParsingParams.New();
        parsingParams.SkipDecryptionErrors = true;
        parsingParams.SkipMacValidation = true;

        byte[] pfxBytes = File.ReadAllBytes(pfxSampleWithPassword);
        Pfx pfx = Pfx.FromDer(pfxBytes, cryptoContext, parsingParams);
        Assert.True(pfx.HasUnknown());
    }
}