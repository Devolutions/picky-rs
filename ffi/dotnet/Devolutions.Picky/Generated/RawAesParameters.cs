// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct AesParameters
{
    private const string NativeLib = "DevolutionsPicky";

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AesParameters_get_type", ExactSpelling = true)]
    public static unsafe extern AesParametersType GetType(AesParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AesParameters_to_initialization_vector", ExactSpelling = true)]
    public static unsafe extern Buffer* ToInitializationVector(AesParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AesParameters_to_authenticated_encryption_parameters", ExactSpelling = true)]
    public static unsafe extern AesAuthEncParams* ToAuthenticatedEncryptionParameters(AesParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AesParameters_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(AesParameters* self);
}
