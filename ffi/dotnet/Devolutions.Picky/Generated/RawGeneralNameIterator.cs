using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct GeneralNameIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralNameIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern GeneralName* Next(GeneralNameIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralNameIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(GeneralNameIterator* handle);
}