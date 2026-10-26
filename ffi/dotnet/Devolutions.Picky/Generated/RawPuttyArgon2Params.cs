using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct PuttyArgon2Params
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyArgon2Params_get_flavor", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PuttyArgon2Flavour GetFlavor(PuttyArgon2Params* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyArgon2Params_get_memory", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern uint GetMemory(PuttyArgon2Params* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyArgon2Params_get_passes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern uint GetPasses(PuttyArgon2Params* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyArgon2Params_get_parallelism", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern uint GetParallelism(PuttyArgon2Params* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyArgon2Params_get_salt", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetSalt(PuttyArgon2Params* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyArgon2Params_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(PuttyArgon2Params* handle);
}