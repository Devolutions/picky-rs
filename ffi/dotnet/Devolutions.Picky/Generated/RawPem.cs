using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Pem
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pem_new", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError New(DiplomatSliceU8 label, DiplomatSliceU8 data);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pem_load_from_file", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError LoadFromFile(DiplomatSliceU8 path);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pem_save_to_file", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError SaveToFile(Pem* handle, DiplomatSliceU8 path);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pem_parse", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPemPickyError Parse(DiplomatSliceU8 input);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pem_get_data_length", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern ulong GetDataLength(Pem* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pem_get_label", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetLabel(Pem* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pem_to_repr", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError ToRepr(Pem* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pem_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Pem* handle);
}