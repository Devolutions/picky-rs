namespace Devolutions.Picky;

public enum PickyErrorKind : int
{
    Generic = 0,
    NotYetValid = 1,
    Expired = 2,
    BadSignature = 3,
    Pkcs12MacValidation = 4,
}