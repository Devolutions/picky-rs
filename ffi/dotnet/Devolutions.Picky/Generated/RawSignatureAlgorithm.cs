using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SignatureAlgorithm
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignatureAlgorithm_new_rsa_pkcs_1v15", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSignatureAlgorithmPickyError NewRsaPkcs1v15(HashAlgorithm hashAlgorithm);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignatureAlgorithm_new_ecdsa", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultSignatureAlgorithmPickyError NewEcdsa(HashAlgorithm hashAlgorithm);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignatureAlgorithm_verify", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError Verify(SignatureAlgorithm* handle, PublicKey* publicKey, DiplomatSliceU8 msg, DiplomatSliceU8 signature);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignatureAlgorithm_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SignatureAlgorithm* handle);
}