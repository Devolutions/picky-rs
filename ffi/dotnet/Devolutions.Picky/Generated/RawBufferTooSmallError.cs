// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct BufferTooSmallError
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "BufferTooSmallError_to_display", ExactSpelling = true)]
    public static unsafe extern void ToDisplay(BufferTooSmallError* self, DiplomatWriteable* writeable);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "BufferTooSmallError_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(BufferTooSmallError* self);
}