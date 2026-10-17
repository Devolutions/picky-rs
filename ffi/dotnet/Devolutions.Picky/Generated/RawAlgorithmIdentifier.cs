using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AlgorithmIdentifier
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifier_is_a", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultBoolPickyError IsA(AlgorithmIdentifier* handle, DiplomatSliceU8 other);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifier_get_oid", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetOid(AlgorithmIdentifier* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifier_get_parameters", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AlgorithmIdentifierParameters* GetParameters(AlgorithmIdentifier* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifier_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AlgorithmIdentifier* handle);
}