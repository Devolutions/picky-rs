using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct RevokedCertificateIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RevokedCertificateIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern RevokedCertificate* Next(RevokedCertificateIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RevokedCertificateIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(RevokedCertificateIterator* handle);
}