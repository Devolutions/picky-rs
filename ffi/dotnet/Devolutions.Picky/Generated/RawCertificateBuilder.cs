using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct CertificateBuilder
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_new", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern CertificateBuilder* New();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_set_valid_from", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetValidFrom(CertificateBuilder* handle, UtcDate* validFrom);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_set_valid_to", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetValidTo(CertificateBuilder* handle, UtcDate* validTo);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_set_issuer_common_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetIssuerCommonName(CertificateBuilder* handle, DiplomatSliceU8 name);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_set_subject_dns_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetSubjectDnsName(CertificateBuilder* handle, DiplomatSliceU8 name);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_set_issuer_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetIssuerKey(CertificateBuilder* handle, PrivateKey* key);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_set_self_signed", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetSelfSigned(CertificateBuilder* handle, [MarshalAs(UnmanagedType.U1)] bool isSelfSigned);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_set_ku_digital_signature", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetKuDigitalSignature(CertificateBuilder* handle, [MarshalAs(UnmanagedType.U1)] bool enable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_set_kp_server_auth", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetKpServerAuth(CertificateBuilder* handle, [MarshalAs(UnmanagedType.U1)] bool enable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_build", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultCertPickyError Build(CertificateBuilder* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateBuilder_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(CertificateBuilder* handle);
}