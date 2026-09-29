using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct StringNestedIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "StringNestedIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern StringIterator* Next(StringNestedIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "StringNestedIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(StringNestedIterator* handle);
}