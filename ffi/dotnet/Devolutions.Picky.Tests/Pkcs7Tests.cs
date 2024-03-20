using Xunit;

namespace Devolutions.Picky.Tests;

public class Pkcs7Tests
{

    private static readonly string p7b = "../../../test_assets/pkcs7.p7b";

    [Fact]
    public void Parse()
    {
        Pem pem = Pem.LoadFromFile(p7b);
        Pkcs7 pkcs7 = Pkcs7.FromPem(pem);

        Pem newPem = pkcs7.ToPem();

        Assert.Equal(pem.ToRepr(), newPem.ToRepr());
    }

}