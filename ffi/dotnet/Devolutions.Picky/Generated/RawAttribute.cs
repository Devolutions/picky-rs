using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Attribute
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Attribute_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetType(Attribute* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Attribute_get_values", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AttributeValues* GetValues(Attribute* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Attribute_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Attribute* handle);
}