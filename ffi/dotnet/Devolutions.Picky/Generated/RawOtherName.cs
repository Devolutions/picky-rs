// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct OtherName
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OtherName_get_type_id", ExactSpelling = true)]
    public static unsafe extern IntPtr GetTypeId(OtherName* self, DiplomatWriteable* writable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OtherName_get_value", ExactSpelling = true)]
    public static unsafe extern Buffer* GetValue(OtherName* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OtherName_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(OtherName* self);
}
