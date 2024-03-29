// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct UnsignedAttributeValue
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UnsignedAttributeValue_get_type", ExactSpelling = true)]
    public static unsafe extern UnsignedAttributeValueType GetType(UnsignedAttributeValue* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UnsignedAttributeValue_to_ms_counter_sign", ExactSpelling = true)]
    public static unsafe extern MsCounterSignIterator* ToMsCounterSign(UnsignedAttributeValue* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UnsignedAttributeValue_to_counter_sign", ExactSpelling = true)]
    public static unsafe extern SignerInfoIterator* ToCounterSign(UnsignedAttributeValue* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UnsignedAttributeValue_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(UnsignedAttributeValue* self);
}
