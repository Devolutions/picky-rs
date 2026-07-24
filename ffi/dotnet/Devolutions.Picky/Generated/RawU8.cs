using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct U8
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "U8_get_value", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetValue(U8* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "U8_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(U8* handle);
}