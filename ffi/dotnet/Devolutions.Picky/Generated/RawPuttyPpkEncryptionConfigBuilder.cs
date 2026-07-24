using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct PuttyPpkEncryptionConfigBuilder
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpkEncryptionConfigBuilder_get_argon2_flavour", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void GetArgon2Flavour(PuttyPpkEncryptionConfigBuilder* handle, PuttyArgon2Flavour argon2Flavour);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpkEncryptionConfigBuilder_set_argon2_memory", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetArgon2Memory(PuttyPpkEncryptionConfigBuilder* handle, uint argon2Memory);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpkEncryptionConfigBuilder_set_argon2_passes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetArgon2Passes(PuttyPpkEncryptionConfigBuilder* handle, uint argon2Passes);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpkEncryptionConfigBuilder_set_argon2_parallelism", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetArgon2Parallelism(PuttyPpkEncryptionConfigBuilder* handle, uint argon2Parallelism);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpkEncryptionConfigBuilder_set_argon2_salt_size", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetArgon2SaltSize(PuttyPpkEncryptionConfigBuilder* handle, uint argon2SaltSize);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpkEncryptionConfigBuilder_build", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PuttyPpkEncryptionConfig* Build(PuttyPpkEncryptionConfigBuilder* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PuttyPpkEncryptionConfigBuilder_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(PuttyPpkEncryptionConfigBuilder* handle);
}