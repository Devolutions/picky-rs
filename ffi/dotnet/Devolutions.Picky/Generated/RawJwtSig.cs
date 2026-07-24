using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct JwtSig
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSig_builder", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern JwtSigBuilder* Builder();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSig_get_content_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetContentType(JwtSig* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSig_get_kid", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetKid(JwtSig* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSig_get_header", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetHeader(JwtSig* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSig_get_claims", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetClaims(JwtSig* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSig_decode", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultJwtSigPickyError Decode(DiplomatSliceU8 compactRepr, PublicKey* publicKey, JwtValidator* validator);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSig_decode_unchecked", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultJwtSigPickyError DecodeUnchecked(DiplomatSliceU8 compactRepr);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSig_encode", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError Encode(JwtSig* handle, PrivateKey* key, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSig_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(JwtSig* handle);
}