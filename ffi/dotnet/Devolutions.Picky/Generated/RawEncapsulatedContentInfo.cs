using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct EncapsulatedContentInfo
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "EncapsulatedContentInfo_content_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ContentType(EncapsulatedContentInfo* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "EncapsulatedContentInfo_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(EncapsulatedContentInfo* handle);
}