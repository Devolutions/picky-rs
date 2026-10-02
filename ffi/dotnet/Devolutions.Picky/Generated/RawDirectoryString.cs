using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct DirectoryString
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryString_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryStringType GetType(DirectoryString* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryString_get_as_string", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetAsString(DirectoryString* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryString_get_as_bytes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetAsBytes(DirectoryString* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryString_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(DirectoryString* handle);
}