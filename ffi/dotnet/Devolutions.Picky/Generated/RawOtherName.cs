using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct OtherName
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "OtherName_get_type_id", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetTypeId(OtherName* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "OtherName_get_value", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetValue(OtherName* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "OtherName_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(OtherName* handle);
}