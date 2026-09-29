using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SpcString
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcString_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SpcStringType GetType(SpcString* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcString_get_as_string", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetAsString(SpcString* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcString_get_as_bytes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetAsBytes(SpcString* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcString_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SpcString* handle);
}