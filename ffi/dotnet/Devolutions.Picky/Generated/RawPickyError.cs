using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct PickyError
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PickyError_to_display", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void ToDisplay(PickyError* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PickyError_print", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Print(PickyError* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PickyError_get_kind", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PickyErrorKind GetKind(PickyError* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PickyError_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(PickyError* handle);
}