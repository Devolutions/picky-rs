using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AlgorithmIdentifierParameters
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifierParameters_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AlgorithmIdentifierParametersType GetType(AlgorithmIdentifierParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifierParameters_to_aes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AesParameters* ToAes(AlgorithmIdentifierParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifierParameters_to_ec", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern EcParameters* ToEc(AlgorithmIdentifierParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifierParameters_to_rsassa_pss", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern RsassaPssParameters* ToRsassaPss(AlgorithmIdentifierParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifierParameters_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AlgorithmIdentifierParameters* handle);
}