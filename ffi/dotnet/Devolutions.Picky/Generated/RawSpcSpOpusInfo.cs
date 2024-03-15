// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct SpcSpOpusInfo
{
    private const string NativeLib = "DevolutionsPicky";

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SpcSpOpusInfo_get_program_name", ExactSpelling = true)]
    public static unsafe extern SpcString* GetProgramName(SpcSpOpusInfo* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SpcSpOpusInfo_get_more_info", ExactSpelling = true)]
    public static unsafe extern SpcLink* GetMoreInfo(SpcSpOpusInfo* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SpcSpOpusInfo_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(SpcSpOpusInfo* self);
}
