// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct AuthorityKeyIdentifier
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AuthorityKeyIdentifier_get_key_identifier", ExactSpelling = true)]
    public static unsafe extern RsBuffer* GetKeyIdentifier(AuthorityKeyIdentifier* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AuthorityKeyIdentifier_get_authority_cert_issuer", ExactSpelling = true)]
    public static unsafe extern GeneralName* GetAuthorityCertIssuer(AuthorityKeyIdentifier* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AuthorityKeyIdentifier_get_authority_cert_serial_number", ExactSpelling = true)]
    public static unsafe extern RsBuffer* GetAuthorityCertSerialNumber(AuthorityKeyIdentifier* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "AuthorityKeyIdentifier_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(AuthorityKeyIdentifier* self);
}
