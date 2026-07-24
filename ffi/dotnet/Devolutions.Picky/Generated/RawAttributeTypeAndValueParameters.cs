using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AttributeTypeAndValueParameters
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AttributeTypeAndValueParametersType GetType(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_common_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToCommonName(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_surname", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToSurname(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_serial_number", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToSerialNumber(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_country_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToCountryName(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_locality_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToLocalityName(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_state_or_province_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToStateOrProvinceName(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_street_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToStreetName(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_organization_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToOrganizationName(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_organizational_unit_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToOrganizationalUnitName(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_email_address", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* ToEmailAddress(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_given_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToGivenName(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_phone", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* ToPhone(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_to_custom", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* ToCustom(AttributeTypeAndValueParameters* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AttributeTypeAndValueParameters_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AttributeTypeAndValueParameters* handle);
}