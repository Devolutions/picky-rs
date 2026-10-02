using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct UnsignedAttributeValue
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UnsignedAttributeValue_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UnsignedAttributeValueType GetType(UnsignedAttributeValue* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UnsignedAttributeValue_to_ms_counter_sign", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern MsCounterSignIterator* ToMsCounterSign(UnsignedAttributeValue* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UnsignedAttributeValue_to_counter_sign", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SignerInfoIterator* ToCounterSign(UnsignedAttributeValue* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UnsignedAttributeValue_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(UnsignedAttributeValue* handle);
}