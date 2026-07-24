using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Pkcs12MacAlgorithmHmac
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12MacAlgorithmHmac_new_hmac", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12MacAlgorithmHmac* NewHmac(Pkcs12HashAlgorithm hashAlgorithm);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12MacAlgorithmHmac_new_hmac_with_iterations", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12MacAlgorithmHmac* NewHmacWithIterations(Pkcs12HashAlgorithm hashAlgorithm, uint iterations);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12MacAlgorithmHmac_hash_algorithm", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12HashAlgorithm HashAlgorithm(Pkcs12MacAlgorithmHmac* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12MacAlgorithmHmac_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Pkcs12MacAlgorithmHmac* handle);
}