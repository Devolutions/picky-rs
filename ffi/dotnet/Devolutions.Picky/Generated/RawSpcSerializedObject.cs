using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SpcSerializedObject
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcSerializedObject_get_class_id", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetClassId(SpcSerializedObject* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcSerializedObject_get_object_id", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetObjectId(SpcSerializedObject* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SpcSerializedObject_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SpcSerializedObject* handle);
}