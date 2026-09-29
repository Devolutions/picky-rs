using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AuthorityKeyIdentifier
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthorityKeyIdentifier_get_key_identifier", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetKeyIdentifier(AuthorityKeyIdentifier* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthorityKeyIdentifier_get_authority_cert_issuer", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern GeneralName* GetAuthorityCertIssuer(AuthorityKeyIdentifier* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthorityKeyIdentifier_get_authority_cert_serial_number", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetAuthorityCertSerialNumber(AuthorityKeyIdentifier* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthorityKeyIdentifier_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AuthorityKeyIdentifier* handle);
}