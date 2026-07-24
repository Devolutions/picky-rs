using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct UnsignedAttributeIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UnsignedAttributeIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UnsignedAttribute* Next(UnsignedAttributeIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UnsignedAttributeIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(UnsignedAttributeIterator* handle);
}