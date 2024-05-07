// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

/// <summary>
/// PuTTY public key format.
/// </summary>
/// <remarks>
/// ### Functionality:
/// - Conversion to/from OpenSSH format.
/// - Encoding/decoding to/from string.
/// - Could be extracted from `PuttyPpk` private keys.
/// <br/>
/// ### Notes
/// - Although top-level containeris similar to PEM, it is not compatible with it because of
/// additional comment field after the header.
/// </remarks>
[StructLayout(LayoutKind.Sequential)]
public partial struct PuttyPublicKey
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    /// <summary>
    /// Converts an OpenSSH public key to a PuTTY public key.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyPublicKey_from_openssh", ExactSpelling = true)]
    public static unsafe extern IntPtr FromOpenssh(SshPublicKey* key);

    /// <summary>
    /// Converts the key to an OpenSSH public key.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyPublicKey_to_openssh", ExactSpelling = true)]
    public static unsafe extern IntPtr ToOpenssh(PuttyPublicKey* self);

    /// <summary>
    /// Get the comment of the public key.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyPublicKey_get_comment", ExactSpelling = true)]
    public static unsafe extern IntPtr GetComment(PuttyPublicKey* self, DiplomatWriteable* writeable);

    /// <summary>
    /// Returns a new public key instance with a different comment.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyPublicKey_with_comment", ExactSpelling = true)]
    public static unsafe extern PuttyPublicKey* WithComment(PuttyPublicKey* self, byte* comment, nuint commentSz);

    /// <summary>
    /// Converts the public key to a string (PuTTY format).
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyPublicKey_to_repr", ExactSpelling = true)]
    public static unsafe extern IntPtr ToRepr(PuttyPublicKey* self, DiplomatWriteable* writeable);

    /// <summary>
    /// Parses and returns the inner key as standard picky key type.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyPublicKey_to_inner_key", ExactSpelling = true)]
    public static unsafe extern IntPtr ToInnerKey(PuttyPublicKey* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyPublicKey_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(PuttyPublicKey* self);
}
