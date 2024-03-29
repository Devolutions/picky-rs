// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct SignerInfo
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignerInfo_get_version", ExactSpelling = true)]
    public static unsafe extern CmsVersion GetVersion(SignerInfo* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignerInfo_get_sid", ExactSpelling = true)]
    public static unsafe extern SingerIdentifier* GetSid(SignerInfo* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignerInfo_get_digest_algorithm", ExactSpelling = true)]
    public static unsafe extern AlgorithmIdentifier* GetDigestAlgorithm(SignerInfo* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignerInfo_get_signature_algorithm", ExactSpelling = true)]
    public static unsafe extern AlgorithmIdentifier* GetSignatureAlgorithm(SignerInfo* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignerInfo_get_signature", ExactSpelling = true)]
    public static unsafe extern VecU8* GetSignature(SignerInfo* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignerInfo_get_unsigned_attributes", ExactSpelling = true)]
    public static unsafe extern UnsignedAttributeIterator* GetUnsignedAttributes(SignerInfo* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignerInfo_get_signed_attributes", ExactSpelling = true)]
    public static unsafe extern AttributeIterator* GetSignedAttributes(SignerInfo* self);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignerInfo_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(SignerInfo* self);
}
