using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky;

public partial class PublicKey
{
    /// Returns the required space in bytes to write the DER representation of the PKCS1 archive.
    ///
    /// When an error occurs, 0 is returned.
    ///
    /// # Safety
    ///
    /// - `public_key` must be a pointer to a valid memory location containing a `PublicKey` object.
	[DllImport(DiplomatNativeLib.Name, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PublicKey_pkcs1_encoded_len", ExactSpelling = true)]
    internal static unsafe extern nuint PublicKey_pkcs1_encoded_len(Raw.PublicKey* public_key);

    /// Serializes an RSA public key into a PKCS1 archive (DER representation).
    ///
    /// Returns 0 (NULL) on success or a pointer to a `PickyError` on failure.
    ///
    /// # Safety
    ///
    /// - `public_key` must be a pointer to a valid memory location containing a `PublicKey` object.
    /// - `dst` must be valid for writes of `count` bytes.
	[DllImport(DiplomatNativeLib.Name, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PublicKey_to_pkcs1", ExactSpelling = true)]
    internal static unsafe extern Raw.PickyError* PublicKey_to_pkcs1(Raw.PublicKey* public_key, byte* dst, nuint count);

    public byte[] ToPkcs1()
    {
        unsafe
        {
            BorrowLease<Raw.PublicKey>? selfLease = null;
            Raw.PickyError* error;
            byte[] pkcs1;
            try
            {
                selfLease = _diplomatHandle.Lease(BorrowKind.Shared);

                nuint count = PublicKey_pkcs1_encoded_len(selfLease.Ptr);

                pkcs1 = new byte[count];

                fixed (byte* pkcs1Ptr = pkcs1)
                {
                    error = PublicKey_to_pkcs1(selfLease.Ptr, pkcs1Ptr, count);
                }
            }
            finally
            {
                selfLease?.Release();
            }

            if (error != null)
            {
                throw new PickyException(new PickyError(error));
            }

            return pkcs1;
        }
    }

    public byte[] ToDer()
    {
        return ToPem().ToData();
    }
}