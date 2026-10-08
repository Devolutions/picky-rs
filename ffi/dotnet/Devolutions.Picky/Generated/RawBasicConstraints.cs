using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct BasicConstraints
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "BasicConstraints_get_ca", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern GetCaResult GetCa(BasicConstraints* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "BasicConstraints_get_pathlen", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern U8* GetPathlen(BasicConstraints* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "BasicConstraints_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(BasicConstraints* handle);
}