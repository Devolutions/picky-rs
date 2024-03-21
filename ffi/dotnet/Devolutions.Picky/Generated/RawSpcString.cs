// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct SpcString
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SpcString_get_type", ExactSpelling = true)]
    public static unsafe extern SpcStringType GetType(SpcString* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SpcString_get_as_string", ExactSpelling = true)]
    public static unsafe extern IntPtr GetAsString(SpcString* self, DiplomatWriteable* writable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SpcString_get_as_bytes", ExactSpelling = true)]
    public static unsafe extern VecU8* GetAsBytes(SpcString* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SpcString_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(SpcString* self);
}
