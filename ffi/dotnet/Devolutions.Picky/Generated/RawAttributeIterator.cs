using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AttributeIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Attribute* Next(AttributeIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AttributeIterator* handle);
}