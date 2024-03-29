// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct AttributeTypeAndValueParameters
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_get_type", ExactSpelling = true)]
    public static unsafe extern AttributeTypeAndValueParametersType GetType(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_common_name", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToCommonName(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_surname", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToSurname(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_serial_number", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToSerialNumber(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_country_name", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToCountryName(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_locality_name", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToLocalityName(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_state_or_province_name", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToStateOrProvinceName(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_street_name", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToStreetName(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_organization_name", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToOrganizationName(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_organizational_unit_name", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToOrganizationalUnitName(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_email_address", ExactSpelling = true)]
    public static unsafe extern VecU8* ToEmailAddress(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_given_name", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToGivenName(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_phone", ExactSpelling = true)]
    public static unsafe extern DirectoryString* ToPhone(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_to_custom", ExactSpelling = true)]
    public static unsafe extern VecU8* ToCustom(AttributeTypeAndValueParameters* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AttributeTypeAndValueParameters_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(AttributeTypeAndValueParameters* self);
}
