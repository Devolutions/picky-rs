using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SpcLink
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcLink_get_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SpcLinkType GetType(SpcLink* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcLink_get_url", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetUrl(SpcLink* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcLink_get_moniker", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SpcSerializedObject* GetMoniker(SpcLink* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcLink_get_file", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SpcString* GetFile(SpcLink* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcLink_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SpcLink* handle);
}