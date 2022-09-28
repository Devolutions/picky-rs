// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct Cert
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    /// <summary>
    /// Parses a X509 certificate from its DER representation.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_from_der", ExactSpelling = true)]
    public static unsafe extern X509FfiResultBoxCertBoxPickyError FromDer(byte* der, nuint derSz);

    /// <summary>
    /// Extracts X509 certificate from PEM object.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_from_pem", ExactSpelling = true)]
    public static unsafe extern X509FfiResultBoxCertBoxPickyError FromPem(Pem* pem);

    /// <summary>
    /// Exports the X509 certificate into a PEM object
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_to_pem", ExactSpelling = true)]
    public static unsafe extern X509FfiResultBoxPemBoxPickyError ToPem(Cert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_get_ty", ExactSpelling = true)]
    public static unsafe extern CertType GetTy(Cert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_get_public_key", ExactSpelling = true)]
    public static unsafe extern PublicKey* GetPublicKey(Cert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_get_cert_type", ExactSpelling = true)]
    public static unsafe extern CertType GetCertType(Cert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_get_valid_not_before", ExactSpelling = true)]
    public static unsafe extern UtcDate* GetValidNotBefore(Cert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_get_valid_not_after", ExactSpelling = true)]
    public static unsafe extern UtcDate* GetValidNotAfter(Cert* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_get_subject_key_id_hex", ExactSpelling = true)]
    public static unsafe extern X509FfiResultVoidBoxPickyError GetSubjectKeyIdHex(Cert* self, DiplomatWriteable* writeable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_get_subject_name", ExactSpelling = true)]
    public static unsafe extern X509FfiResultVoidBoxPickyError GetSubjectName(Cert* self, DiplomatWriteable* writeable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_get_issuer_name", ExactSpelling = true)]
    public static unsafe extern X509FfiResultVoidBoxPickyError GetIssuerName(Cert* self, DiplomatWriteable* writeable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Cert_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(Cert* self);
}
