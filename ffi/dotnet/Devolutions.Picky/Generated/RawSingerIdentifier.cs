// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct SingerIdentifier
{
    private const string NativeLib = "DevolutionsPicky";

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SingerIdentifier_get_issure_and_serial_number", ExactSpelling = true)]
    public static unsafe extern IssuerAndSerialNumber* GetIssureAndSerialNumber(SingerIdentifier* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SingerIdentifier_get_subject_key_identifier", ExactSpelling = true)]
    public static unsafe extern Buffer* GetSubjectKeyIdentifier(SingerIdentifier* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SingerIdentifier_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(SingerIdentifier* self);
}
