// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct Argon2Params
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    /// <summary>
    /// Create new parameters.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Argon2Params_new", ExactSpelling = true)]
    public static unsafe extern Argon2Params* New();

    /// <summary>
    /// Sets the memory size in 1 KiB blocks. Between 1 and (2^32)-1.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Argon2Params_set_m_cost", ExactSpelling = true)]
    public static unsafe extern void SetMCost(Argon2Params* self, uint value);

    /// <summary>
    /// Sets the number of iterations. Between 1 and (2^32)-1.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Argon2Params_set_t_cost", ExactSpelling = true)]
    public static unsafe extern void SetTCost(Argon2Params* self, uint value);

    /// <summary>
    /// Sets the degree of parallelism. Between 1 and 255.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Argon2Params_set_p_cost", ExactSpelling = true)]
    public static unsafe extern void SetPCost(Argon2Params* self, uint value);

    /// <summary>
    /// Sets the size of the KDF output in bytes. Default 32.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Argon2Params_set_output_len", ExactSpelling = true)]
    public static unsafe extern void SetOutputLen(Argon2Params* self, nuint value);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Argon2Params_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(Argon2Params* self);
}
