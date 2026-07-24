using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SafeBag
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_new_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSafeBagPickyError NewKey(PrivateKey* key);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_new_encrypted_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSafeBagPickyError NewEncryptedKey(PrivateKey* key, Pkcs12Encryption* encryption, Pkcs12CryptoContext* cryptoContext);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_new_certificate", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSafeBagPickyError NewCertificate(Cert* cert);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_add_attribute", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void AddAttribute(SafeBag* handle, Pkcs12Attribute* attribute);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_get_kind", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SafeBagKind GetKind(SafeBag* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_get_private_key", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern PrivateKey* GetPrivateKey(SafeBag* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_get_certificate", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Cert* GetCertificate(SafeBag* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_contains_friendly_name", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool ContainsFriendlyName(SafeBag* handle, DiplomatSliceU8 value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_contains_local_key_id", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool ContainsLocalKeyId(SafeBag* handle, DiplomatSliceU8 value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_attributes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern Pkcs12AttributeIterator* Attributes(SafeBag* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SafeBag_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SafeBag* handle);
}