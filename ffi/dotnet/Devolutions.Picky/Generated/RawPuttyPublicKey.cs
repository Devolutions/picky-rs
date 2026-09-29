using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct PuttyPublicKey
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPublicKey_from_openssh", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPuttyPublicKeyPickyError FromOpenssh(SshPublicKey* key);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPublicKey_to_openssh", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSshPublicKeyPickyError ToOpenssh(PuttyPublicKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPublicKey_get_comment", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetComment(PuttyPublicKey* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPublicKey_with_comment", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PuttyPublicKey* WithComment(PuttyPublicKey* handle, DiplomatSliceU8 comment);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPublicKey_to_repr", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ToRepr(PuttyPublicKey* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPublicKey_to_inner_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPublicKeyPickyError ToInnerKey(PuttyPublicKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPublicKey_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(PuttyPublicKey* handle);
}