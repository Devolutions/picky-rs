using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct DirectoryName
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryName_new", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryName* New();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryName_new_common_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryName* NewCommonName(DiplomatSliceU8 name);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryName_find_common_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* FindCommonName(DirectoryName* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryName_add_attr", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void AddAttr(DirectoryName* handle, NameAttr attr, DiplomatSliceU8 value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryName_add_email", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError AddEmail(DirectoryName* handle, DiplomatSliceU8 email);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryName_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(DirectoryName* handle);
}