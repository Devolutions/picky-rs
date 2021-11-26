using System;

using Xunit;

namespace Devolutions.Picky.Tests;

public class HashTest
{
    private static readonly byte[] input = { 25, 30, 35, 40, 45, 50 };
    private static readonly byte[] sha2256 = { 131, 104, 46, 44, 153, 22, 0, 4, 241, 26, 211, 125, 4, 53, 28, 221, 71, 49, 82, 154, 250, 243, 236, 113, 129, 159, 57, 202, 167, 88, 89, 160 };
    private static readonly byte[] sha3512 = { 234, 141, 99, 88, 87, 13, 149, 201, 193, 74, 190, 180, 35, 69, 139, 138, 210, 42, 3, 178, 31, 253, 89, 132, 151, 35, 78, 96, 151, 118, 31, 201, 128, 175, 221, 200, 65, 38, 179, 231, 175, 41, 172, 233, 118, 232, 71, 15, 206, 104, 56, 117, 166, 224, 240, 28, 193, 10, 1, 35, 87, 248, 201, 25 };

    [Fact]
    public void Sha2256()
    {
        Assert.Equal(HashAlgorithm.SHA2_256.Digest(input), sha2256);
    }

    [Fact]
    public void Sha3512()
    {
        Assert.Equal(HashAlgorithm.SHA3_512.Digest(input), sha3512);
    }
}