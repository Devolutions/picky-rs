using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct CertificateList
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateList_get_tbs_cert_list", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern TbsCertList* GetTbsCertList(CertificateList* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateList_get_signature_algorithm", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AlgorithmIdentifier* GetSignatureAlgorithm(CertificateList* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateList_get_signature_value", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetSignatureValue(CertificateList* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateList_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(CertificateList* handle);
}