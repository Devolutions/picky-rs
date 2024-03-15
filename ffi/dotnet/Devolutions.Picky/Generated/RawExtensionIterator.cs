// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct ExtensionIterator
{
    private const string NativeLib = "DevolutionsPicky";

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "ExtensionIterator_next", ExactSpelling = true)]
    public static unsafe extern Extension* Next(ExtensionIterator* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "ExtensionIterator_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(ExtensionIterator* self);
}
