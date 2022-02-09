// Automatically generated by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

/// <summary>
/// UTC date and time.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public partial struct UtcDate
{
    private const string NativeLib = "picky";

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_new", ExactSpelling = true)]
    public static unsafe extern UtcDate* New(ushort year, byte month, byte day, byte hour, byte minute, byte second);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_ymd", ExactSpelling = true)]
    public static unsafe extern UtcDate* Ymd(ushort year, byte month, byte day);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_now", ExactSpelling = true)]
    public static unsafe extern UtcDate* Now();

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_from_timestamp", ExactSpelling = true)]
    public static unsafe extern IntPtr FromTimestamp(long timestamp);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_get_timestamp", ExactSpelling = true)]
    public static unsafe extern IntPtr GetTimestamp(UtcDate* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_get_month", ExactSpelling = true)]
    public static unsafe extern byte GetMonth(UtcDate* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_get_day", ExactSpelling = true)]
    public static unsafe extern byte GetDay(UtcDate* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_get_hour", ExactSpelling = true)]
    public static unsafe extern byte GetHour(UtcDate* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_get_minute", ExactSpelling = true)]
    public static unsafe extern byte GetMinute(UtcDate* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_get_second", ExactSpelling = true)]
    public static unsafe extern byte GetSecond(UtcDate* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_get_year", ExactSpelling = true)]
    public static unsafe extern ushort GetYear(UtcDate* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "UtcDate_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(UtcDate* self);
}
