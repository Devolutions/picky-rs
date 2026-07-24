using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Time
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Time_get_year", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ushort GetYear(Time* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Time_get_month", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetMonth(Time* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Time_get_day", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetDay(Time* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Time_get_hour", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetHour(Time* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Time_get_minute", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetMinute(Time* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Time_get_second", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetSecond(Time* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Time_is_utc", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool IsUtc(Time* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Time_is_generalized", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool IsGeneralized(Time* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Time_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Time* handle);
}