using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Pkcs12Attribute
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12Attribute_new_friendly_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPkcs12AttributePickyError NewFriendlyName(DiplomatSliceU8 name);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12Attribute_new_local_key_id", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12Attribute* NewLocalKeyId(DiplomatSliceU8 value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12Attribute_get_kind", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12AttributeKind GetKind(Pkcs12Attribute* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12Attribute_get_friendly_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetFriendlyName(Pkcs12Attribute* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12Attribute_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Pkcs12Attribute* handle);
}