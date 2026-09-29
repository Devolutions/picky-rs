using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AttributeValues
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeValues_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AttributeValueType GetType(AttributeValues* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeValues_to_custom", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* ToCustom(AttributeValues* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeValues_to_extensions", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ExtensionIterator* ToExtensions(AttributeValues* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeValues_to_content_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern StringIterator* ToContentType(AttributeValues* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeValues_to_spc_statement_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern StringNestedIterator* ToSpcStatementType(AttributeValues* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeValues_to_message_digest", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern StringIterator* ToMessageDigest(AttributeValues* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeValues_to_signing_time", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UTCTimeIterator* ToSigningTime(AttributeValues* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeValues_to_spc_sp_opus_info", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SpcSpOpusInfoIterator* ToSpcSpOpusInfo(AttributeValues* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeValues_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AttributeValues* handle);
}