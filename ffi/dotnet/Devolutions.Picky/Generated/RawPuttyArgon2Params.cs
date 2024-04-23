// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

/// <summary>
/// Argon2 key derivation function parameters.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public partial struct PuttyArgon2Params
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyArgon2Params_get_flavor", ExactSpelling = true)]
    public static unsafe extern PuttyArgon2Flavour GetFlavor(PuttyArgon2Params* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyArgon2Params_get_memory", ExactSpelling = true)]
    public static unsafe extern uint GetMemory(PuttyArgon2Params* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyArgon2Params_get_passes", ExactSpelling = true)]
    public static unsafe extern uint GetPasses(PuttyArgon2Params* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyArgon2Params_get_parallelism", ExactSpelling = true)]
    public static unsafe extern uint GetParallelism(PuttyArgon2Params* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyArgon2Params_get_salt", ExactSpelling = true)]
    public static unsafe extern VecU8* GetSalt(PuttyArgon2Params* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PuttyArgon2Params_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(PuttyArgon2Params* self);
}
