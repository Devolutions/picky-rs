using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct VecU8
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "VecU8_from_bytes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* FromBytes(DiplomatSliceU8 bytes);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "VecU8_get_length", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern nuint GetLength(VecU8* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "VecU8_fill", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidBufferTooSmallError Fill(VecU8* handle, DiplomatSliceMutU8 buffer);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "VecU8_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(VecU8* handle);
}