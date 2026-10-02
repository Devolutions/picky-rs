using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SafeBagIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBagIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SafeBag* Next(SafeBagIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBagIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SafeBagIterator* handle);
}