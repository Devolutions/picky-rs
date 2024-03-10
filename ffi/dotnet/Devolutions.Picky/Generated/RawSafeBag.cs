// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

/// <summary>
/// PFX safe bag, the polymorphic container for all the data in a PKCS12 archive.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public partial struct SafeBag
{
    private const string NativeLib = "DevolutionsPicky";

    /// <summary>
    /// Creates new safe bag holding a private key.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_new_key", ExactSpelling = true)]
    public static unsafe extern Pkcs12FfiResultBoxSafeBagBoxPickyError NewKey(PrivateKey* key);

    /// <summary>
    /// Creates new safe bag holding an encrypted private key.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_new_encrypted_key", ExactSpelling = true)]
    public static unsafe extern Pkcs12FfiResultBoxSafeBagBoxPickyError NewEncryptedKey(PrivateKey* key, Pkcs12Encryption* encryption, Pkcs12CryptoContext* cryptoContext);

    /// <summary>
    /// Creates new safe bag holding a certificate.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_new_certificate", ExactSpelling = true)]
    public static unsafe extern Pkcs12FfiResultBoxSafeBagBoxPickyError NewCertificate(Cert* cert);

    /// <summary>
    /// Adds a PKCS12 attribute to this safe bag.
    /// </summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_add_attribute", ExactSpelling = true)]
    public static unsafe extern void AddAttribute(SafeBag* self, Pkcs12Attribute* attribute);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_get_kind", ExactSpelling = true)]
    public static unsafe extern SafeBagKind GetKind(SafeBag* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_get_private_key", ExactSpelling = true)]
    public static unsafe extern PrivateKey* GetPrivateKey(SafeBag* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_get_certificate", ExactSpelling = true)]
    public static unsafe extern Cert* GetCertificate(SafeBag* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_contains_friendly_name", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static unsafe extern bool ContainsFriendlyName(SafeBag* self, byte* value, nuint valueSz);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_contains_local_key_id", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static unsafe extern bool ContainsLocalKeyId(SafeBag* self, byte* value, nuint valueSz);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_attributes", ExactSpelling = true)]
    public static unsafe extern Pkcs12AttributeIterator* Attributes(SafeBag* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SafeBag_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(SafeBag* self);
}
