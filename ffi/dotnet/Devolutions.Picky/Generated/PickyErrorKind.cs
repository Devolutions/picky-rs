// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

/// <summary>
/// Kind associated to a Picky Error
/// </summary>
public enum PickyErrorKind
{
    /// <summary>
    /// Generic Picky error
    /// </summary>
    Generic = 0,
    /// <summary>
    /// Token or certificate not yet valid
    /// </summary>
    NotYetValid = 1,
    /// <summary>
    /// Token or certificate expired
    /// </summary>
    Expired = 2,
    /// <summary>
    /// Bad signature for token or certificate
    /// </summary>
    BadSignature = 3,
    /// <summary>
    /// MAC validation failed (wrong password or corrupted data)
    /// </summary>
    Pkcs12MacValidation = 4,
}
