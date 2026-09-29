using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SpcSpOpusInfoIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcSpOpusInfoIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SpcSpOpusInfo* Next(SpcSpOpusInfoIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcSpOpusInfoIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SpcSpOpusInfoIterator* handle);
}