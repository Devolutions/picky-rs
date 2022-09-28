// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct SignatureAlgorithm
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignatureAlgorithm_new_rsa_pkcs_1v15", ExactSpelling = true)]
    public static unsafe extern SignatureFfiResultBoxSignatureAlgorithmBoxPickyError NewRsaPkcs1v15(HashAlgorithm hashAlgorithm);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignatureAlgorithm_verify", ExactSpelling = true)]
    public static unsafe extern SignatureFfiResultVoidBoxPickyError Verify(SignatureAlgorithm* self, PublicKey* publicKey, byte* msg, nuint msgSz, byte* signature, nuint signatureSz);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SignatureAlgorithm_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(SignatureAlgorithm* self);
}
