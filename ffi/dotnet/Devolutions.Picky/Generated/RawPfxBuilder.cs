// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

/// <summary>
/// PFX (PKCS12 archive) builder.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public partial struct PfxBuilder
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PfxBuilder_init", ExactSpelling = true)]
    public static unsafe extern PfxBuilder* Init(Pkcs12CryptoContext* cryptoContext);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PfxBuilder_add_safe_bag_to_current_safe_contents", ExactSpelling = true)]
    public static unsafe extern void AddSafeBagToCurrentSafeContents(PfxBuilder* self, SafeBag* safeBag);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PfxBuilder_mark_safe_contents_as_ready", ExactSpelling = true)]
    public static unsafe extern void MarkSafeContentsAsReady(PfxBuilder* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PfxBuilder_mark_encrypted_safe_contents_as_ready", ExactSpelling = true)]
    public static unsafe extern IntPtr MarkEncryptedSafeContentsAsReady(PfxBuilder* self, Pkcs12Encryption* encryption);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PfxBuilder_set_hmac_algorithm", ExactSpelling = true)]
    public static unsafe extern void SetHmacAlgorithm(PfxBuilder* self, Pkcs12MacAlgorithmHmac* macAlgorithm);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PfxBuilder_build", ExactSpelling = true)]
    public static unsafe extern IntPtr Build(PfxBuilder* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PfxBuilder_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(PfxBuilder* self);
}
