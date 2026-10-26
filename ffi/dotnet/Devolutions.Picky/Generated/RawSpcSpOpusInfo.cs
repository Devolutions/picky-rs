using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SpcSpOpusInfo
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcSpOpusInfo_get_program_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SpcString* GetProgramName(SpcSpOpusInfo* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcSpOpusInfo_get_more_info", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SpcLink* GetMoreInfo(SpcSpOpusInfo* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcSpOpusInfo_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SpcSpOpusInfo* handle);
}