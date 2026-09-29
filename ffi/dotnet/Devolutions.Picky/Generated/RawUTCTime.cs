using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct UTCTime
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UTCTime_get_year", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ushort GetYear(UTCTime* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UTCTime_get_month", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetMonth(UTCTime* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UTCTime_get_day", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetDay(UTCTime* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UTCTime_get_hour", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetHour(UTCTime* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UTCTime_get_minute", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetMinute(UTCTime* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UTCTime_get_second", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern byte GetSecond(UTCTime* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "UTCTime_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(UTCTime* handle);
}