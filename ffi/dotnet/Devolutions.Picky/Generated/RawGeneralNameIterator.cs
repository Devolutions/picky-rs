// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct GeneralNameIterator
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "GeneralNameIterator_next", ExactSpelling = true)]
    public static unsafe extern GeneralName* Next(GeneralNameIterator* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "GeneralNameIterator_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(GeneralNameIterator* self);
}
