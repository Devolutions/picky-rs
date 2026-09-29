using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct CertificateChoices
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateChoices_get_certificate", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetCertificate(CertificateChoices* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateChoices_get_other", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetOther(CertificateChoices* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateChoices_is_certificate", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool IsCertificate(CertificateChoices* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateChoices_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(CertificateChoices* handle);
}