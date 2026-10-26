using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct ExtensionView
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ExtensionViewType GetType(ExtensionView* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_to_authority_key_identifier", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AuthorityKeyIdentifier* ToAuthorityKeyIdentifier(ExtensionView* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_to_subject_key_identifier", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* ToSubjectKeyIdentifier(ExtensionView* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_to_key_usage", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* ToKeyUsage(ExtensionView* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_to_subject_alt_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern GeneralNameIterator* ToSubjectAltName(ExtensionView* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_to_issuer_alt_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern GeneralNameIterator* ToIssuerAltName(ExtensionView* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_to_basic_constraints", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern BasicConstraints* ToBasicConstraints(ExtensionView* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_to_extended_key_usage", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern OidIterator* ToExtendedKeyUsage(ExtensionView* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_to_generic", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* ToGeneric(ExtensionView* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_to_crl_number", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* ToCrlNumber(ExtensionView* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "ExtensionView_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(ExtensionView* handle);
}