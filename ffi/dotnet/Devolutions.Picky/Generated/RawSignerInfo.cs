using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SignerInfo
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignerInfo_get_version", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern CmsVersion GetVersion(SignerInfo* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignerInfo_get_sid", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SingerIdentifier* GetSid(SignerInfo* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignerInfo_get_digest_algorithm", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AlgorithmIdentifier* GetDigestAlgorithm(SignerInfo* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignerInfo_get_signature_algorithm", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AlgorithmIdentifier* GetSignatureAlgorithm(SignerInfo* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignerInfo_get_signature", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern VecU8* GetSignature(SignerInfo* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignerInfo_get_unsigned_attributes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern UnsignedAttributeIterator* GetUnsignedAttributes(SignerInfo* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignerInfo_get_signed_attributes", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AttributeIterator* GetSignedAttributes(SignerInfo* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignerInfo_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SignerInfo* handle);
}