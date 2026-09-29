using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct UnsignedAttribute
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UnsignedAttribute_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetType(UnsignedAttribute* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UnsignedAttribute_get_values", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UnsignedAttributeValue* GetValues(UnsignedAttribute* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UnsignedAttribute_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(UnsignedAttribute* handle);
}