// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct CertVec
{
    private const string NativeLib = "DevolutionsPicky";

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "CertVec_next", ExactSpelling = true)]
    public static unsafe extern Cert* Next(CertVec* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "CertVec_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(CertVec* self);
}
