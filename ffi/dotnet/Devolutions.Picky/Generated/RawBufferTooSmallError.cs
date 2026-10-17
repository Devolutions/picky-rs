using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct BufferTooSmallError
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "BufferTooSmallError_to_display", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void ToDisplay(BufferTooSmallError* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "BufferTooSmallError_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(BufferTooSmallError* handle);
}