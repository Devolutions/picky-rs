// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct Pkcs7
{
    private const string NativeLib = "DevolutionsPicky";

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pkcs7_from_der", ExactSpelling = true)]
    public static unsafe extern Pkcs7FfiResultBoxPkcs7BoxPickyError FromDer(byte* data, nuint dataSz);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pkcs7_from_pem", ExactSpelling = true)]
    public static unsafe extern Pkcs7FfiResultBoxPkcs7BoxPickyError FromPem(Pem* pem);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pkcs7_from_pem_str", ExactSpelling = true)]
    public static unsafe extern Pkcs7FfiResultBoxPkcs7BoxPickyError FromPemStr(byte* pemStr, nuint pemStrSz);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pkcs7_to_der", ExactSpelling = true)]
    public static unsafe extern Pkcs7FfiResultBoxDerBoxPickyError ToDer(Pkcs7* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pkcs7_to_pem", ExactSpelling = true)]
    public static unsafe extern Pkcs7FfiResultBoxPemBoxPickyError ToPem(Pkcs7* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pkcs7_digest_algorithms", ExactSpelling = true)]
    public static unsafe extern AlgorithmIdentifiers* DigestAlgorithms(Pkcs7* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pkcs7_signer_infos", ExactSpelling = true)]
    public static unsafe extern SignerInfos* SignerInfos(Pkcs7* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pkcs7_encapsulated_content_info", ExactSpelling = true)]
    public static unsafe extern EncapsulatedContentInfo* EncapsulatedContentInfo(Pkcs7* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pkcs7_decode_certificates", ExactSpelling = true)]
    public static unsafe extern CertVec* DecodeCertificates(Pkcs7* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pkcs7_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(Pkcs7* self);
}
