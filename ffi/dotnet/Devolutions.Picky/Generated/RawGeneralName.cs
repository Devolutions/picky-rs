using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct GeneralName
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralName_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern GeneralNameType GetType(GeneralName* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralName_to_other_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern OtherName* ToOtherName(GeneralName* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralName_to_rfc822_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ToRfc822Name(GeneralName* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralName_to_dns_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ToDnsName(GeneralName* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralName_to_directory_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AttributeTypeAndValueNestedIterator* ToDirectoryName(GeneralName* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralName_to_edi_party_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern EdiPartyName* ToEdiPartyName(GeneralName* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralName_to_uri", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ToUri(GeneralName* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralName_to_ip_address", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* ToIpAddress(GeneralName* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralName_to_registered_id", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ToRegisteredId(GeneralName* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "GeneralName_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(GeneralName* handle);
}