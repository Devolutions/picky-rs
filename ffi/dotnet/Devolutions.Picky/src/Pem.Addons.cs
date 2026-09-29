using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky;

public partial class Pem
{
    /// Returned data should not be modified!
    [DllImport(DiplomatNativeLib.Name, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Pem_peek_data", ExactSpelling = true)]
    internal static unsafe extern IntPtr PeekData(Raw.Pem* self, out nuint len);

    public byte[] ToData()
    {
        unsafe
        {
            // The lease keeps the Pem alive and unmutated until the peeked bytes are copied.
            BorrowLease<Raw.Pem>? selfLease = null;
            try
            {
                selfLease = _diplomatHandle.Lease(BorrowKind.Shared);

                nuint dataLen;
                IntPtr dataPtr = PeekData(selfLease.Ptr, out dataLen);

                byte[] retVal = new byte[dataLen];
                Marshal.Copy(dataPtr, retVal, 0, (int)dataLen);

                return retVal;
            }
            finally
            {
                selfLease?.Release();
            }
        }
    }
}