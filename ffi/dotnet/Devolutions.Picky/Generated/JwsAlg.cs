namespace Devolutions.Picky;

public enum JwsAlg : int
{
    Rs256 = 0,
    Rs384 = 1,
    Rs512 = 2,
    Hs256 = 3,
    Hs384 = 4,
    Hs512 = 5,
    Es256 = 6,
    Es384 = 7,
    Es512 = 8,
    Ps256 = 9,
    Ps384 = 10,
    Ps512 = 11,
    EdDsa = 12,
    Ed25519 = 13,
}