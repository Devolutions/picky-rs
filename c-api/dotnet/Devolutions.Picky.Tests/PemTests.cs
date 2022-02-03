using System;

using Xunit;

namespace Devolutions.Picky.Tests;

public class PemTests
{
    private static readonly string certPemRepr = @"-----BEGIN CERTIFICATE-----
MIIDPzCCAiegAwIBAgIBATANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER
MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN
MTEwMjEyMTQ0NDA2WhcNMjEwMjEyMTQ0NDA2WjA8MQswCQYDVQQGEwJOTDERMA8G
A1UECgwIUG9sYXJTU0wxGjAYBgNVBAMMEVBvbGFyU1NMIFNlcnZlciAxMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQIfPUBq1VVTi/027oJlLhVhXom/
uOhFkNvuiBZS0/FDUEeWEllkh2v9K+BG+XO+3c+S4ZFb7Wagb4kpeUWA0INq1UFD
d185fAkER4KwVzlw7aPsFRkeqDMIR8EFQqn9TMO0390GH00QUUBncxMPQPhtgSVf
CrFTxjB+FTms+Vruf5KepgVb5xOXhbUjktnUJAbVCSWJdQfdphqPPwkZvq1lLGTr
lZvc/kFeF6babFtpzAK6FCwWJJxK3M3Q91Jnc/EtoCP9fvQxyi1wyokLBNsupk9w
bp7OvViJ4lNZnm5akmXiiD8MlBmj3eXonZUT7Snbq3AS3FrKaxerUoJUsQIDAQAB
o00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBQfdNY/KcF0dEU7BRIsPai9Q1kCpjAf
BgNVHSMEGDAWgBS0WuSls97SUva51aaVD+s+vMf9/zANBgkqhkiG9w0BAQUFAAOC
AQEAm9GKWy4Z6eS483GoR5omwx32meCStm/vFuW+nozRwqwTG5d2Etx4TPnz73s8
fMtM1QB0QbfBDDHxfGymEsKwICmCkJszKE7c03j3mkddrrvN2eIYiL6358S3yHMj
iLVCraRUoEm01k7iytjxrcKb//hxFvHoxD1tdMqbuvjMlTS86kJSrkUMDw68UzfL
jvo3oVjiexfasjsICXFNoncjthKtS7v4zrsgXNPz92h58NgXnDtQU+Eb9tVA9kUs
Ln/az3v5DdgrNoAO60zK1zYAmekLil7pgba/jBLPeAQ2fZVgFxttKv33nUnUBzKA
Od8i323fM5dQS1qQpBjBc/5fPw==
-----END CERTIFICATE-----";

    [Fact]
    public void Parse()
    {
        PickyPem pem = PickyPem.Parse(certPemRepr);
        Assert.Equal("CERTIFICATE", pem.Label);
        Assert.Equal((ulong)835, pem.DataLength);
        Assert.Equal(certPemRepr, pem.ToRepr());
    }

    [Fact]
    public void Smoke()
    {
        PickyPem fromReprPem = PickyPem.Parse(certPemRepr);
        // TODO: need support for returning buffer of bytes
        // PickyPem fromDataPem = PickyPem.New(fromReprPem.Label, fromReprPem.ToData());
        // Assert.Equal(certPemRepr, fromDataPem.ToRepr());
    }

    [Fact]
    public void LoadFromFileFailure()
    {
        Action act = () => PickyPem.LoadFromFile("path/to/nowhere");
        Assert.Throws<PickyException>(act);
    }
}