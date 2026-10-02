using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct EcParameters
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "EcParameters_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(EcParameters* handle);
}