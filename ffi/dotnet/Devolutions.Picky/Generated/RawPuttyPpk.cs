using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct PuttyPpk
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_generate_rsa", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPpkPickyError GenerateRsa(nuint bits, DiplomatSliceU8 comment);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_generate_ec", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPpkPickyError GenerateEc(EcCurve curve, DiplomatSliceU8 comment);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_generate_ed25519", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPpkPickyError GenerateEd25519(DiplomatSliceU8 comment);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_to_repr", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ToRepr(PuttyPpk* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_parse", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPpkPickyError Parse(DiplomatSliceU8 ppk);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_from_openssh", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPpkPickyError FromOpenssh(SshPrivateKey* key);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_to_openssh", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSshPrivateKeyPickyError ToOpenssh(PuttyPpk* handle, DiplomatSliceU8 passphrase);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_from_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPpkPickyError FromKey(PrivateKey* privateKey);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_get_public_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPublicKeyPickyError GetPublicKey(PuttyPpk* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_get_private_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPrivateKeyPickyError GetPrivateKey(PuttyPpk* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_extract_putty_public_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPublicKeyPickyError ExtractPuttyPublicKey(PuttyPpk* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_get_version", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PuttyPpkVersion GetVersion(PuttyPpk* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_get_algorithm", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PuttyPpkKeyAlgorithm GetAlgorithm(PuttyPpk* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_get_comment", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetComment(PuttyPpk* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_with_comment", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPpkPickyError WithComment(PuttyPpk* handle, DiplomatSliceU8 comment);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_to_version", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPpkPickyError ToVersion(PuttyPpk* handle, PuttyPpkVersion version);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_is_encrypted", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool IsEncrypted(PuttyPpk* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_argon2_params", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PuttyArgon2Params* Argon2Params(PuttyPpk* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_decrypt", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPpkPickyError Decrypt(PuttyPpk* handle, DiplomatSliceU8 passphrase);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_encrypt", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPpkPickyError Encrypt(PuttyPpk* handle, DiplomatSliceU8 passphrase, PuttyPpkEncryptionConfig* config);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpk_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(PuttyPpk* handle);
}