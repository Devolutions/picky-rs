using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct PfxBuilder
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PfxBuilder_init", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PfxBuilder* Init(Pkcs12CryptoContext* cryptoContext);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PfxBuilder_add_safe_bag_to_current_safe_contents", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void AddSafeBagToCurrentSafeContents(PfxBuilder* handle, SafeBag* safeBag);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PfxBuilder_mark_safe_contents_as_ready", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void MarkSafeContentsAsReady(PfxBuilder* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PfxBuilder_mark_encrypted_safe_contents_as_ready", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError MarkEncryptedSafeContentsAsReady(PfxBuilder* handle, Pkcs12Encryption* encryption);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PfxBuilder_set_hmac_algorithm", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetHmacAlgorithm(PfxBuilder* handle, Pkcs12MacAlgorithmHmac* macAlgorithm);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PfxBuilder_build", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultPfxPickyError Build(PfxBuilder* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "PfxBuilder_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(PfxBuilder* handle);
}