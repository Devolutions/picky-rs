using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AttributeTypeAndValueNestedIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueNestedIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AttributeTypeAndValueIterator* Next(AttributeTypeAndValueNestedIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueNestedIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AttributeTypeAndValueNestedIterator* handle);
}