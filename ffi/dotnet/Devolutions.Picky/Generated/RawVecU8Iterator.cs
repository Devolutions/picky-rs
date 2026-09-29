using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct VecU8Iterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "VecU8Iterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* Next(VecU8Iterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "VecU8Iterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(VecU8Iterator* handle);
}