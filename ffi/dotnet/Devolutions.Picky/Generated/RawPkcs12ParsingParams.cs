using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Pkcs12ParsingParams
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12ParsingParams_new", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12ParsingParams* New();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12ParsingParams_set_skip_soft_parsing_errors", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetSkipSoftParsingErrors(Pkcs12ParsingParams* handle, [MarshalAs(UnmanagedType.U1)] bool value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12ParsingParams_set_skip_decryption_errors", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetSkipDecryptionErrors(Pkcs12ParsingParams* handle, [MarshalAs(UnmanagedType.U1)] bool value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12ParsingParams_set_skip_mac_validation", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetSkipMacValidation(Pkcs12ParsingParams* handle, [MarshalAs(UnmanagedType.U1)] bool value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Pkcs12ParsingParams_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Pkcs12ParsingParams* handle);
}