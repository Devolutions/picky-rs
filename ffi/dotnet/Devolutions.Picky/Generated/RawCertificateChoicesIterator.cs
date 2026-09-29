using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct CertificateChoicesIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateChoicesIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern CertificateChoices* Next(CertificateChoicesIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertificateChoicesIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(CertificateChoicesIterator* handle);
}