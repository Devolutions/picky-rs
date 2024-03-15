// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct AttributeValues
{
    private const string NativeLib = "DevolutionsPicky";

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeValues_get_type", ExactSpelling = true)]
    public static unsafe extern AttributeValueType GetType(AttributeValues* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeValues_to_custom", ExactSpelling = true)]
    public static unsafe extern Buffer* ToCustom(AttributeValues* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeValues_to_extensions", ExactSpelling = true)]
    public static unsafe extern ExtensionIterator* ToExtensions(AttributeValues* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeValues_to_content_type", ExactSpelling = true)]
    public static unsafe extern StringIterator* ToContentType(AttributeValues* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeValues_to_spc_statement_type", ExactSpelling = true)]
    public static unsafe extern StringNestedIterator* ToSpcStatementType(AttributeValues* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeValues_to_message_digest", ExactSpelling = true)]
    public static unsafe extern StringIterator* ToMessageDigest(AttributeValues* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeValues_to_signing_time", ExactSpelling = true)]
    public static unsafe extern UTCTimeIterator* ToSigningTime(AttributeValues* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeValues_to_spc_sp_opus_info", ExactSpelling = true)]
    public static unsafe extern SpcSpOpusInfoIterator* ToSpcSpOpusInfo(AttributeValues* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeValues_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(AttributeValues* self);
}
