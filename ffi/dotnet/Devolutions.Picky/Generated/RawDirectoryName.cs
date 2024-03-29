// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct DirectoryName
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "DirectoryName_new", ExactSpelling = true)]
    public static unsafe extern DirectoryName* New();

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "DirectoryName_new_common_name", ExactSpelling = true)]
    public static unsafe extern DirectoryName* NewCommonName(byte* name, nuint nameSz);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "DirectoryName_find_common_name", ExactSpelling = true)]
    public static unsafe extern DirectoryString* FindCommonName(DirectoryName* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "DirectoryName_add_attr", ExactSpelling = true)]
    public static unsafe extern void AddAttr(DirectoryName* self, NameAttr attr, byte* value, nuint valueSz);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "DirectoryName_add_email", ExactSpelling = true)]
    public static unsafe extern IntPtr AddEmail(DirectoryName* self, byte* email, nuint emailSz);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "DirectoryName_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(DirectoryName* self);
}
