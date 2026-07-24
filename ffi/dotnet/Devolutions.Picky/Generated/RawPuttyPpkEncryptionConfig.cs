using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct PuttyPpkEncryptionConfig
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpkEncryptionConfig_default", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PuttyPpkEncryptionConfig* Default();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpkEncryptionConfig_builder", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PuttyPpkEncryptionConfigBuilder* Builder();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpkEncryptionConfig_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(PuttyPpkEncryptionConfig* handle);
}