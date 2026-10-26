using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct ExtensionIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Extension* Next(ExtensionIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(ExtensionIterator* handle);
}