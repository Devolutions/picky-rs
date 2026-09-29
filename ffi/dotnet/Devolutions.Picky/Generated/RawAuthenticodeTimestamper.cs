using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AuthenticodeTimestamper
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeTimestamper_new", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultAuthenticodeTimestamperPickyError New(DiplomatSliceU8 url);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeTimestamper_timestamp", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPkcs7PickyError Timestamp(AuthenticodeTimestamper* handle, VecU8* digest, HashAlgorithm hashAlgo);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeTimestamper_modify_signed_data", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void ModifySignedData(AuthenticodeTimestamper* handle, Pkcs7* token, SignedData* signedData);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeTimestamper_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AuthenticodeTimestamper* handle);
}