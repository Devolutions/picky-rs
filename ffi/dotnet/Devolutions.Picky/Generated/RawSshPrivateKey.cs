// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

/// <summary>
/// SSH Private Key.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public partial struct SshPrivateKey
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    /// <summary>
    /// Generates a new SSH RSA Private Key.
    /// </summary>
    /// <remarks>
    /// No passphrase is set if `passphrase` is empty.
    /// <br/>
    /// No comment is set if `comment` is empty.
    /// <br/>
    /// This is slow in debug builds.
    /// </remarks>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_generate_rsa", ExactSpelling = true)]
    public static unsafe extern IntPtr GenerateRsa(nuint bits, byte* passphrase, nuint passphraseSz, byte* comment, nuint commentSz);

    /// <summary>
    /// Generates a new SSH EC Private Key.
    /// </summary>
    /// <remarks>
    /// No passphrase is set if `passphrase` is empty.
    /// <br/>
    /// No comment is set if `comment` is empty.
    /// </remarks>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_generate_ec", ExactSpelling = true)]
    public static unsafe extern IntPtr GenerateEc(EcCurve curve, byte* passphrase, nuint passphraseSz, byte* comment, nuint commentSz);

    /// <summary>
    /// Generates a new SSH ed25519 Private Key.
    /// </summary>
    /// <remarks>
    /// No passphrase is set if `passphrase` is empty.
    /// <br/>
    /// No comment is set if `comment` is empty.
    /// </remarks>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_generate_ed25519", ExactSpelling = true)]
    public static unsafe extern IntPtr GenerateEd25519(byte* passphrase, nuint passphraseSz, byte* comment, nuint commentSz);

    /// <summary>
    /// Extracts SSH Private Key from PEM object.
    /// </summary>
    /// <remarks>
    /// No passphrase is set if `passphrase` is empty.
    /// </remarks>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_from_pem", ExactSpelling = true)]
    public static unsafe extern IntPtr FromPem(Pem* pem, byte* passphrase, nuint passphraseSz);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_from_key", ExactSpelling = true)]
    public static unsafe extern IntPtr FromKey(PrivateKey* key);

    /// <summary>
    /// Exports the SSH Private Key into a PEM object
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_to_pem", ExactSpelling = true)]
    public static unsafe extern IntPtr ToPem(SshPrivateKey* self);

    /// <summary>
    /// Returns the SSH Private Key string representation.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_to_repr", ExactSpelling = true)]
    public static unsafe extern IntPtr ToRepr(SshPrivateKey* self, DiplomatWriteable* writeable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_get_cipher_name", ExactSpelling = true)]
    public static unsafe extern IntPtr GetCipherName(SshPrivateKey* self, DiplomatWriteable* writeable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_get_comment", ExactSpelling = true)]
    public static unsafe extern IntPtr GetComment(SshPrivateKey* self, DiplomatWriteable* writeable);

    /// <summary>
    /// Extracts the public part of this private key
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_to_public_key", ExactSpelling = true)]
    public static unsafe extern SshPublicKey* ToPublicKey(SshPrivateKey* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshPrivateKey_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(SshPrivateKey* self);
}
