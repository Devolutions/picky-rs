using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct TbsCertList
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "TbsCertList_get_version", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Version GetVersion(TbsCertList* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "TbsCertList_get_signature_algorithm", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AlgorithmIdentifier* GetSignatureAlgorithm(TbsCertList* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "TbsCertList_get_issuer", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetIssuer(TbsCertList* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "TbsCertList_get_this_upate", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Time* GetThisUpate(TbsCertList* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "TbsCertList_get_next_update", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Time* GetNextUpdate(TbsCertList* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "TbsCertList_get_revoked_certificates", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern RevokedCertificateIterator* GetRevokedCertificates(TbsCertList* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "TbsCertList_get_extenstions", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ExtensionIterator* GetExtenstions(TbsCertList* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "TbsCertList_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(TbsCertList* handle);
}