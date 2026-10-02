using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct RsassaPssParameters
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RsassaPssParameters_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(RsassaPssParameters* handle);
}