using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct MsCounterSignIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MsCounterSignIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern MsCounterSign* Next(MsCounterSignIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MsCounterSignIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(MsCounterSignIterator* handle);
}