using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Pkcs12Encryption
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12Encryption_default", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12Encryption* Default();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12Encryption_new_pbes2", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12Encryption* NewPbes2(Pbes2Cipher cipher, Pkcs12HashAlgorithm hmacKdf);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12Encryption_new_pbes1", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12Encryption* NewPbes1(Pbes1Cipher cipher);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12Encryption_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Pkcs12Encryption* handle);
}