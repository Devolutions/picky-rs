using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky;

public partial class Pem
{
	// TODO: maybe this should be part of the Diplomat namespace in DiplomatRuntime.cs
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

	/// Returned data should not be modified!
	[DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pem_peek_data", ExactSpelling = true)]
	internal static unsafe extern IntPtr PeekData(Raw.Pem* self, out nuint len);

    public byte[] ToData()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Pem");
            }

			nuint dataLen;
            IntPtr dataPtr = PeekData(_inner, out dataLen);

			byte[] retVal = new byte[dataLen];
			Marshal.Copy(dataPtr, retVal, 0, (int)dataLen);

			return retVal;
        }
    }
}
