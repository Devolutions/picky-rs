using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Pkcs12CryptoContext
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12CryptoContext_with_password", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPkcs12CryptoContextPickyError WithPassword(DiplomatSliceU8 password);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12CryptoContext_no_password", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPkcs12CryptoContextPickyError NoPassword();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12CryptoContext_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Pkcs12CryptoContext* handle);
}