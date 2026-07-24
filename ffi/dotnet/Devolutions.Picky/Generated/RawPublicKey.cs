using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct PublicKey
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PublicKey_from_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPublicKeyPickyError FromPem(Pem* pem);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PublicKey_from_der", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPublicKeyPickyError FromDer(DiplomatSliceU8 der);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PublicKey_from_pkcs1", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPublicKeyPickyError FromPkcs1(DiplomatSliceU8 der);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PublicKey_to_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError ToPem(PublicKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PublicKey_to_pkcs1_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError ToPkcs1Pem(PublicKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PublicKey_get_kind", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern KeyKind GetKind(PublicKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PublicKey_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(PublicKey* handle);
}