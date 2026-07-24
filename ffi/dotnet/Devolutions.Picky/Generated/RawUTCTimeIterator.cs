using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct UTCTimeIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UTCTimeIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UTCTime* Next(UTCTimeIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UTCTimeIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(UTCTimeIterator* handle);
}