using System;

using Xunit;

namespace Devolutions.Picky.Tests;

public class Argon2Tests
{
    [Fact]
    public void HashPasswordSmoke()
    {
        Argon2Params parameters = Argon2Params.New();
        Argon2 argon2 = Argon2.New(Argon2Algorithm.Argon2id, parameters);
        string password_hash = argon2.HashPassword("hunter42");
        Assert.Equal("$argon2id$", password_hash.Substring(0, 10));
    }
}
