using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SshPublicKey
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPublicKey_parse", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSshPublicKeyPickyError Parse(DiplomatSliceU8 repr);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPublicKey_to_repr", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ToRepr(SshPublicKey* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPublicKey_get_comment", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetComment(SshPublicKey* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPublicKey_fingerprint_md5", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVecU8PickyError FingerprintMd5(SshPublicKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPublicKey_fingerprint_sha1", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVecU8PickyError FingerprintSha1(SshPublicKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPublicKey_fingerprint_sha256", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVecU8PickyError FingerprintSha256(SshPublicKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SshPublicKey_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SshPublicKey* handle);
}