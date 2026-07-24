using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SingerIdentifier
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SingerIdentifier_get_issure_and_serial_number", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern IssuerAndSerialNumber* GetIssureAndSerialNumber(SingerIdentifier* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SingerIdentifier_get_subject_key_identifier", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetSubjectKeyIdentifier(SingerIdentifier* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SingerIdentifier_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SingerIdentifier* handle);
}