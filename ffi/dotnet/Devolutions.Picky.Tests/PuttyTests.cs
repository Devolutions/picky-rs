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
        using (PuttyPpkEncryptionConfig config = PuttyPpkEncryptionConfig.Default())
        using (PuttyPpk encrypted = ppk.Encrypt("hunter2", config))
        using (PuttyPublicKey ppkPublicKey = ppk.ExtractPuttyPublicKey())
        {
            Assert.True(encrypted.IsEncrypted());
            publicKey = ppkPublicKey.ToRepr();
            encryptedRepr = encrypted.ToRepr();
        }

        using PuttyPpk parsed = PuttyPpk.Parse(encryptedRepr);
        Assert.Throws<PickyException>(() => parsed.Decrypt("wrong"));

        using PuttyPpk decrypted = parsed.Decrypt("hunter2");
        using PuttyPublicKey decryptedPublicKey = decrypted.ExtractPuttyPublicKey();
        Assert.False(decrypted.IsEncrypted());
        Assert.Contains("Encryption: none", decrypted.ToRepr());
        Assert.Equal(publicKey, decryptedPublicKey.ToRepr());
    }
}
