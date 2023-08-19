using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky;

public partial class PublicKey
{
	// FIXME: maybe this should be part of the Diplomat namespace in DiplomatRuntime.cs
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    /// Returns the required space in bytes to write the DER representation of the PKCS1 archive.
    ///
    /// When an error occurs, 0 is returned.
    ///
    /// # Safety
    ///
    /// - `public_key` must be a pointer to a valid memory location containing a `PublicKey` object.
	[DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PublicKey_pkcs1_encoded_len", ExactSpelling = true)]
	internal static unsafe extern nuint PublicKey_pkcs1_encoded_len(Raw.PublicKey* public_key);

    /// Serializes an RSA public key into a PKCS1 archive (DER representation).
    ///
    /// Returns 0 (NULL) on success or a pointer to a `PickyError` on failure.
    ///
    /// # Safety
    ///
    /// - `public_key` must be a pointer to a valid memory location containing a `PublicKey` object.
    /// - `dst` must be valid for writes of `count` bytes.
	[DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "PublicKey_to_pkcs1", ExactSpelling = true)]
	internal static unsafe extern Raw.PickyError* PublicKey_to_pkcs1(Raw.PublicKey* public_key, byte* dst, nuint count);

    public byte[] ToPkcs1()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PublicKey");
            }

			nuint count = PublicKey_pkcs1_encoded_len(_inner);

			byte[] pkcs1 = new byte[count];
            Raw.PickyError* error;

            fixed (byte* pkcs1Ptr = pkcs1)
            {
                error = PublicKey_to_pkcs1(_inner, pkcs1Ptr, count);
            }

            if (error != null) {
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
