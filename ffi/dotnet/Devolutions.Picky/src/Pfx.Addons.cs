using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky;

public partial class Pfx
{
	// FIXME: maybe this should be part of the Diplomat namespace in DiplomatRuntime.cs
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    /// Returns the required space in bytes to write the DER representation of this PKCS12 archive.
    ///
    /// When an error occurs, 0 is returned.
    ///
    /// # Safety
    ///
    /// - `pfx` must be a pointer to a valid memory location containing a `Pfx` object.
	[DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pfx_der_encoded_len", ExactSpelling = true)]
	internal static unsafe extern nuint Pfx_der_encoded_len(Raw.Pfx* self);

    /// Serializes the PKCS12 archive into DER representation.
    ///
    /// Returns 0 (NULL) on success or a pointer to a `PickyError` on failure.
    ///
    /// # Safety
    ///
    /// - `pfx` must be a pointer to a valid memory location containing a `Pfx` object.
    /// - `dst` must be valid for writes of `count` bytes.
	[DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pfx_to_der", ExactSpelling = true)]
	internal static unsafe extern Raw.PickyError* Pfx_to_der(Raw.Pfx* self, byte* dst, nuint count);

    public byte[] ToDer()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Pfx");
            }

			nuint count = Pfx_der_encoded_len(_inner);

			byte[] der = new byte[count];
            Raw.PickyError* error;

            fixed (byte* derPtr = der)
            {
                error = Pfx_to_der(_inner, derPtr, count);
            }

            if (error != null) {
                throw new PickyException(new PickyError(error));
            }

			return der;
        }
    }
}
