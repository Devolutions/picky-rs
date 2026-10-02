using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AttributeTypeAndValue
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValue_get_type_id", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetTypeId(AttributeTypeAndValue* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValue_get_value", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AttributeTypeAndValueParameters* GetValue(AttributeTypeAndValue* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValue_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AttributeTypeAndValue* handle);
}