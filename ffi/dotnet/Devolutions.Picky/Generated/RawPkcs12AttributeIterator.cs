using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Pkcs12AttributeIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12AttributeIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12Attribute* Next(Pkcs12AttributeIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12AttributeIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Pkcs12AttributeIterator* handle);
}