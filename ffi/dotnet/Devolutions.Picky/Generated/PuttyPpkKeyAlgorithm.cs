namespace Devolutions.Picky;

public enum PuttyPpkKeyAlgorithm : int
{
    Rsa = 0,
    Dss = 1,
    EcdsaSha2Nistp256 = 2,
    EcdsaSha2Nistp384 = 3,
    EcdsaSha2Nistp521 = 4,
    Ed25519 = 5,
    Ed448 = 6,
}