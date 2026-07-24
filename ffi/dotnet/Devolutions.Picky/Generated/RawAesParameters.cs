using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AesParameters
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AesParameters_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AesParametersType GetType(AesParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AesParameters_to_initialization_vector", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* ToInitializationVector(AesParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AesParameters_to_authenticated_encryption_parameters", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AesAuthEncParams* ToAuthenticatedEncryptionParameters(AesParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AesParameters_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AesParameters* handle);
}