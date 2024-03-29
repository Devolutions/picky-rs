// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct Time
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Time_get_year", ExactSpelling = true)]
    public static unsafe extern ushort GetYear(Time* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Time_get_month", ExactSpelling = true)]
    public static unsafe extern byte GetMonth(Time* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Time_get_day", ExactSpelling = true)]
    public static unsafe extern byte GetDay(Time* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Time_get_hour", ExactSpelling = true)]
    public static unsafe extern byte GetHour(Time* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Time_get_minute", ExactSpelling = true)]
    public static unsafe extern byte GetMinute(Time* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Time_get_second", ExactSpelling = true)]
    public static unsafe extern byte GetSecond(Time* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Time_is_utc", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static unsafe extern bool IsUtc(Time* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Time_is_generalized", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static unsafe extern bool IsGeneralized(Time* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Time_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(Time* self);
}
