using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct RevocationInfoChoice
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RevocationInfoChoice_get_crl", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern CertificateList* GetCrl(RevocationInfoChoice* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RevocationInfoChoice_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(RevocationInfoChoice* handle);
}