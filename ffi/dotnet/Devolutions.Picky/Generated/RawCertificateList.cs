// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct CertificateList
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "CertificateList_get_tbs_cert_list", ExactSpelling = true)]
    public static unsafe extern TbsCertList* GetTbsCertList(CertificateList* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "CertificateList_get_signature_algorithm", ExactSpelling = true)]
    public static unsafe extern AlgorithmIdentifier* GetSignatureAlgorithm(CertificateList* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "CertificateList_get_signature_value", ExactSpelling = true)]
    public static unsafe extern VecU8* GetSignatureValue(CertificateList* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "CertificateList_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(CertificateList* self);
}