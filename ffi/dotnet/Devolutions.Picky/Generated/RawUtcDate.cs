using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct UtcDate
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_new", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UtcDate* New(ushort year, byte month, byte day, byte hour, byte minute, byte second);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_ymd", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UtcDate* Ymd(ushort year, byte month, byte day);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_now", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UtcDate* Now();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_from_timestamp", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultUtcDatePickyError FromTimestamp(long timestamp);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_get_timestamp", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultLongPickyError GetTimestamp(UtcDate* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_get_month", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetMonth(UtcDate* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_get_day", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetDay(UtcDate* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_get_hour", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetHour(UtcDate* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_get_minute", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetMinute(UtcDate* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_get_second", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetSecond(UtcDate* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_get_year", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ushort GetYear(UtcDate* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UtcDate_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(UtcDate* handle);
}