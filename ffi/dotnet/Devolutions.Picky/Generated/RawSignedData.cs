using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SignedData
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignedData_get_version", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern CmsVersion GetVersion(SignedData* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignedData_get_digest_algorithms", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AlgorithmIdentifierIterator* GetDigestAlgorithms(SignedData* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignedData_get_content_info", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern EncapsulatedContentInfo* GetContentInfo(SignedData* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignedData_get_crls", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern RevocationInfoChoiceIterator* GetCrls(SignedData* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignedData_get_certificates", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern CertificateChoicesIterator* GetCertificates(SignedData* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignedData_get_signers_infos", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SignerInfoIterator* GetSignersInfos(SignedData* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignedData_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SignedData* handle);
}