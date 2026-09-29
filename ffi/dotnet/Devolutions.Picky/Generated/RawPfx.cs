using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Pfx
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pfx_builder", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PfxBuilder* Builder(Pkcs12CryptoContext* cryptoContext);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pfx_from_der", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPfxPickyError FromDer(DiplomatSliceU8 der, Pkcs12CryptoContext* cryptoContext, Pkcs12ParsingParams* parsingParams);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pfx_hmac_algorithm", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12MacAlgorithmHmac* HmacAlgorithm(Pfx* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pfx_save_to_file", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError SaveToFile(Pfx* handle, DiplomatSliceU8 path);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pfx_safe_bags", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SafeBagIterator* SafeBags(Pfx* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pfx_has_unknown", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool HasUnknown(Pfx* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pfx_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Pfx* handle);
}