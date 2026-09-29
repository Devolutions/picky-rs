using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Pkcs7
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs7_from_der", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPkcs7PickyError FromDer(DiplomatSliceU8 data);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs7_from_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPkcs7PickyError FromPem(Pem* pem);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs7_to_der", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVecU8PickyError ToDer(Pkcs7* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs7_to_pem", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError ToPem(Pkcs7* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs7_digest_algorithms", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AlgorithmIdentifierIterator* DigestAlgorithms(Pkcs7* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs7_signer_infos", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SignerInfoIterator* SignerInfos(Pkcs7* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs7_encapsulated_content_info", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern EncapsulatedContentInfo* EncapsulatedContentInfo(Pkcs7* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs7_decode_certificates", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern CertIterator* DecodeCertificates(Pkcs7* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs7_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Pkcs7* handle);
}