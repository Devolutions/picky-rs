using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct RsString
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RsString_from_string", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern RsString* FromString(DiplomatSliceU8 s);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RsString_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(RsString* handle);
}