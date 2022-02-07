// Automatically generated by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct SshCert
{
    private const string NativeLib = "picky";

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_builder", ExactSpelling = true)]
    public static unsafe extern SshCertBuilder* Builder();

    /// <summary>
    /// Parses string representation of a SSH Certificate.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_parse", ExactSpelling = true)]
    public static unsafe extern SshFfiResultBoxSshCertBoxPickyError Parse(byte* repr, nuint reprSz);

    /// <summary>
    /// Returns the SSH Certificate string representation.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_to_repr", ExactSpelling = true)]
    public static unsafe extern SshFfiResultVoidBoxPickyError ToRepr(SshCert* self, DiplomatWriteable* writeable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_get_public_key", ExactSpelling = true)]
    public static unsafe extern SshPublicKey* GetPublicKey(SshCert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_get_ssh_key_type", ExactSpelling = true)]
    public static unsafe extern SshCertKeyType GetSshKeyType(SshCert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_get_cert_type", ExactSpelling = true)]
    public static unsafe extern SshCertType GetCertType(SshCert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_get_valid_after", ExactSpelling = true)]
    public static unsafe extern ulong GetValidAfter(SshCert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_get_valid_before", ExactSpelling = true)]
    public static unsafe extern ulong GetValidBefore(SshCert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_get_signature_key", ExactSpelling = true)]
    public static unsafe extern SshPublicKey* GetSignatureKey(SshCert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_get_key_id", ExactSpelling = true)]
    public static unsafe extern SshFfiResultVoidBoxPickyError GetKeyId(SshCert* self, DiplomatWriteable* writeable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_get_comment", ExactSpelling = true)]
    public static unsafe extern SshFfiResultVoidBoxPickyError GetComment(SshCert* self, DiplomatWriteable* writeable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SshCert_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(SshCert* self);
}
