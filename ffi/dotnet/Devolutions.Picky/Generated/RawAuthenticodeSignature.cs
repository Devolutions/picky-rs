using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AuthenticodeSignature
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_new", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultAuthenticodeSignaturePickyError New(Pkcs7* pkcs7, VecU8* fileHash, ShaVariant hashAlgorithm, PrivateKey* privateKey, RsString* programName);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_timestamp", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError Timestamp(AuthenticodeSignature* handle, AuthenticodeTimestamper* timestamper, HashAlgorithm hashAlgo);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_from_der", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultAuthenticodeSignaturePickyError FromDer(VecU8* der);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_from_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultAuthenticodeSignaturePickyError FromPem(Pem* pem);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_from_pem_str", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultAuthenticodeSignaturePickyError FromPemStr(DiplomatSliceU8 pem);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_to_der", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVecU8PickyError ToDer(AuthenticodeSignature* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_to_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError ToPem(AuthenticodeSignature* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_signing_certificate", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultCertPickyError SigningCertificate(AuthenticodeSignature* handle, CertIterator* cert);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_authenticode_verifier", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AuthenticodeValidator* AuthenticodeVerifier(AuthenticodeSignature* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_file_hash", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* FileHash(AuthenticodeSignature* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_authenticate_attributes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AttributeIterator* AuthenticateAttributes(AuthenticodeSignature* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_unauthenticated_attributes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UnsignedAttributeIterator* UnauthenticatedAttributes(AuthenticodeSignature* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeSignature_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AuthenticodeSignature* handle);
}