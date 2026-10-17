using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AttributeTypeAndValueIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AttributeTypeAndValue* Next(AttributeTypeAndValueIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AttributeTypeAndValueIterator* handle);
}