namespace Devolutions.Picky;

public enum SafeBagKind : int
{
    PrivateKey = 0,
    Certificate = 1,
    Secret = 2,
    Unknown = 3,
}