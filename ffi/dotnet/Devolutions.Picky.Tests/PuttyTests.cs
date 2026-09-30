using Xunit;

namespace Devolutions.Picky.Tests;

public class PuttyTests
{
    [Fact]
    public void EncryptedPpkRoundTrips()
    {
        string publicKey;
        string encryptedRepr;
        using (PuttyPpk ppk = PuttyPpk.GenerateEd25519("test@picky.com"))
        using (PuttyPpk encrypted = ppk.Encrypt("hunter2", PuttyPpkEncryptionConfig.Default()))
        {
            Assert.True(encrypted.IsEncrypted());
            publicKey = ppk.ExtractPuttyPublicKey().ToRepr();
            encryptedRepr = encrypted.ToRepr();
        }

        using PuttyPpk parsed = PuttyPpk.Parse(encryptedRepr);
        Assert.Throws<PickyException>(() => parsed.Decrypt("wrong"));

        using PuttyPpk decrypted = parsed.Decrypt("hunter2");
        PuttyPublicKey decryptedPublicKey = decrypted.ExtractPuttyPublicKey();
        Assert.False(decrypted.IsEncrypted());
        Assert.Contains("Encryption: none", decrypted.ToRepr());
        Assert.Equal(publicKey, decryptedPublicKey.ToRepr());
    }
}
