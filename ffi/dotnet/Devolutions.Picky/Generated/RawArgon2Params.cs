using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Argon2Params
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Argon2Params_new", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Argon2Params* New();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Argon2Params_set_m_cost", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetMCost(Argon2Params* handle, uint value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Argon2Params_set_t_cost", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetTCost(Argon2Params* handle, uint value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Argon2Params_set_p_cost", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetPCost(Argon2Params* handle, uint value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Argon2Params_set_output_len", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetOutputLen(Argon2Params* handle, nuint value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Argon2Params_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Argon2Params* handle);
}