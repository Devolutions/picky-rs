using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct CertIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Cert* Next(CertIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "CertIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(CertIterator* handle);
}