using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct RevokedCertificate
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RevokedCertificate_get_user_certificate", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetUserCertificate(RevokedCertificate* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RevokedCertificate_get_revocation_date", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Time* GetRevocationDate(RevokedCertificate* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RevokedCertificate_get_extensions", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ExtensionIterator* GetExtensions(RevokedCertificate* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RevokedCertificate_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(RevokedCertificate* handle);
}