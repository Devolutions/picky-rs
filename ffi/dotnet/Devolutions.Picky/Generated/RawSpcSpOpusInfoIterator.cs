// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct SpcSpOpusInfoIterator
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SpcSpOpusInfoIterator_next", ExactSpelling = true)]
    public static unsafe extern SpcSpOpusInfo* Next(SpcSpOpusInfoIterator* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SpcSpOpusInfoIterator_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(SpcSpOpusInfoIterator* self);
}
