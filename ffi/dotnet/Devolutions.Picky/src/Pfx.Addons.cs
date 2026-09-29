using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky;

public partial class Pfx
{
    /// Returns the required space in bytes to write the DER representation of this PKCS12 archive.
    ///
    /// When an error occurs, 0 is returned.
    ///
    /// # Safety
    ///
    /// - `pfx` must be a pointer to a valid memory location containing a `Pfx` object.
	[DllImport(DiplomatNativeLib.Name, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pfx_der_encoded_len", ExactSpelling = true)]
    internal static unsafe extern nuint Pfx_der_encoded_len(Raw.Pfx* pfx);

    /// Serializes the PKCS12 archive into DER representation.
    ///
    /// Returns 0 (NULL) on success or a pointer to a `PickyError` on failure.
    ///
    /// # Safety
    ///
    /// - `pfx` must be a pointer to a valid memory location containing a `Pfx` object.
    /// - `dst` must be valid for writes of `count` bytes.
	[DllImport(DiplomatNativeLib.Name, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pfx_to_der", ExactSpelling = true)]
    internal static unsafe extern Raw.PickyError* Pfx_to_der(Raw.Pfx* pfx, byte* dst, nuint count);

    public byte[] ToDer()
    {
        unsafe
        {
            BorrowLease<Raw.Pfx>? selfLease = null;
            Raw.PickyError* error;
            byte[] der;
            try
            {
                selfLease = _diplomatHandle.Lease(BorrowKind.Shared);

                nuint count = Pfx_der_encoded_len(selfLease.Ptr);

                der = new byte[count];

                fixed (byte* derPtr = der)
                {
                    error = Pfx_to_der(selfLease.Ptr, derPtr, count);
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

            return der;
        }
    }
}