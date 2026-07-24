using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SshCertBuilder
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_init", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SshCertBuilder* Init();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_set_cert_key_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetCertKeyType(SshCertBuilder* handle, SshCertKeyType keyType);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_set_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetKey(SshCertBuilder* handle, SshPublicKey* key);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_set_serial", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetSerial(SshCertBuilder* handle, ulong serial);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_set_cert_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetCertType(SshCertBuilder* handle, SshCertType certType);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_set_key_id", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetKeyId(SshCertBuilder* handle, DiplomatSliceU8 keyId);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_set_valid_before", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetValidBefore(SshCertBuilder* handle, ulong validBefore);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_set_valid_after", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetValidAfter(SshCertBuilder* handle, ulong validAfter);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_set_signature_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetSignatureKey(SshCertBuilder* handle, SshPrivateKey* signatureKey);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_set_signature_algo", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetSignatureAlgo(SshCertBuilder* handle, SignatureAlgorithm* signatureAlgo);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_set_comment", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetComment(SshCertBuilder* handle, DiplomatSliceU8 comment);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_build", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSshCertPickyError Build(SshCertBuilder* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshCertBuilder_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SshCertBuilder* handle);
}