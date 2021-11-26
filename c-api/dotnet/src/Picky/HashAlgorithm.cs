namespace Devolutions.Picky;

public enum HashAlgorithm
{
    MD5 = Native.Raw.PICKY_HASH_MD5,
    SHA1 = Native.Raw.PICKY_HASH_SHA1,
    SHA2_224 = Native.Raw.PICKY_HASH_SHA2_224,
    SHA2_256 = Native.Raw.PICKY_HASH_SHA2_256,
    SHA2_384 = Native.Raw.PICKY_HASH_SHA2_384,
    SHA2_512 = Native.Raw.PICKY_HASH_SHA2_512,
    SHA3_384 = Native.Raw.PICKY_HASH_SHA3_384,
    SHA3_512 = Native.Raw.PICKY_HASH_SHA3_512,
}