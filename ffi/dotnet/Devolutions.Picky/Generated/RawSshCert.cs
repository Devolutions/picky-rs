using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SshCert
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_builder", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SshCertBuilder* Builder();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_parse", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSshCertPickyError Parse(DiplomatSliceU8 repr);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_to_repr", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ToRepr(SshCert* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_get_public_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SshPublicKey* GetPublicKey(SshCert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_get_ssh_key_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SshCertKeyType GetSshKeyType(SshCert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_get_cert_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SshCertType GetCertType(SshCert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_get_valid_after", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ulong GetValidAfter(SshCert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_get_valid_before", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ulong GetValidBefore(SshCert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_get_signature_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SshPublicKey* GetSignatureKey(SshCert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_get_key_id", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetKeyId(SshCert* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_get_comment", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetComment(SshCert* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCert_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SshCert* handle);
}