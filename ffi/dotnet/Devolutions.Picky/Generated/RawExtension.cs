using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Extension
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Extension_get_extn_id", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetExtnId(Extension* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Extension_get_critical", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool GetCritical(Extension* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Extension_get_value", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ExtensionView* GetValue(Extension* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Extension_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Extension* handle);
}