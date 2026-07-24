using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Cert
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_from_der", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultCertPickyError FromDer(DiplomatSliceU8 der);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_from_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultCertPickyError FromPem(Pem* pem);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_to_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError ToPem(Cert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_get_ty", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern CertType GetTy(Cert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_get_public_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PublicKey* GetPublicKey(Cert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_get_cert_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern CertType GetCertType(Cert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_get_valid_not_before", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UtcDate* GetValidNotBefore(Cert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_get_valid_not_after", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UtcDate* GetValidNotAfter(Cert* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_get_subject_key_id_hex", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetSubjectKeyIdHex(Cert* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_get_subject_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetSubjectName(Cert* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_get_issuer_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetIssuerName(Cert* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Cert_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Cert* handle);
}