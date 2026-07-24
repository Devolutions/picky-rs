using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct PrivateKey
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_from_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPrivateKeyPickyError FromPem(Pem* pem);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_from_pkcs8", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPrivateKeyPickyError FromPkcs8(DiplomatSliceU8 pkcs8);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_from_pem_str", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPrivateKeyPickyError FromPemStr(DiplomatSliceU8 pem);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_generate_rsa", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPrivateKeyPickyError GenerateRsa(nuint bits);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_generate_ec", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPrivateKeyPickyError GenerateEc(EcCurve curve);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_generate_ed", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPrivateKeyPickyError GenerateEd(EdAlgorithm algorithm, [MarshalAs(UnmanagedType.U1)] bool writePublicKey);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_to_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError ToPem(PrivateKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_to_pkcs1_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError ToPkcs1Pem(PrivateKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_to_public_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPublicKeyPickyError ToPublicKey(PrivateKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_get_kind", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern KeyKind GetKind(PrivateKey* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PrivateKey_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(PrivateKey* handle);
}