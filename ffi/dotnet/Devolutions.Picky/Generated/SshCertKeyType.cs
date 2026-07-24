namespace Devolutions.Picky;

public enum SshCertKeyType : int
{
    SshRsaV01 = 0,
    SshDssV01 = 1,
    RsaSha2256v01 = 2,
    RsaSha2512v01 = 3,
    EcdsaSha2Nistp256V01 = 4,
    EcdsaSha2Nistp384V01 = 5,
    EcdsaSha2Nistp521V01 = 6,
    SshEd25519V01 = 7,
    SkSshSha2Nistp256V01 = 8,
    SkSshEd25519V01 = 9,
}