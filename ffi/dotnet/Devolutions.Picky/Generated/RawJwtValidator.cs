using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct JwtValidator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtValidator_strict", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern JwtValidator* Strict(long numericDate, ushort leeway);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtValidator_lenient", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern JwtValidator* Lenient(long numericDate, ushort leeway);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtValidator_no_check", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern JwtValidator* NoCheck();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtValidator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(JwtValidator* handle);
}