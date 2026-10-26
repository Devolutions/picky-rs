using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SshPrivateKey
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_generate_rsa", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSshPrivateKeyPickyError GenerateRsa(nuint bits, DiplomatSliceU8 passphrase, DiplomatSliceU8 comment);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_generate_ec", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSshPrivateKeyPickyError GenerateEc(EcCurve curve, DiplomatSliceU8 passphrase, DiplomatSliceU8 comment);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_generate_ed25519", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSshPrivateKeyPickyError GenerateEd25519(DiplomatSliceU8 passphrase, DiplomatSliceU8 comment);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_from_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSshPrivateKeyPickyError FromPem(Pem* pem, DiplomatSliceU8 passphrase);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_from_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSshPrivateKeyPickyError FromKey(PrivateKey* key);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_inner_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PrivateKey* InnerKey(SshPrivateKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_to_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError ToPem(SshPrivateKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_to_repr", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ToRepr(SshPrivateKey* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_get_cipher_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetCipherName(SshPrivateKey* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_get_comment", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetComment(SshPrivateKey* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_to_public_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SshPublicKey* ToPublicKey(SshPrivateKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPrivateKey_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SshPrivateKey* handle);
}