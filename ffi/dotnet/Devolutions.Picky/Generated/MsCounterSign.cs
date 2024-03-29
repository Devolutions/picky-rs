// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class MsCounterSign: IDisposable
{
    private unsafe Raw.MsCounterSign* _inner;

    public string Oid
    {
        get
        {
            return GetOid();
        }
    }

    public SignedData SignedData
    {
        get
        {
            return GetSignedData();
        }
    }

    /// <summary>
    /// Creates a managed <c>MsCounterSign</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe MsCounterSign(Raw.MsCounterSign* handle)
    {
        _inner = handle;
    }

    /// <exception cref="PickyException"></exception>
    public void GetOid(DiplomatWriteable writable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("MsCounterSign");
            }
            IntPtr resultPtr = Raw.MsCounterSign.GetOid(_inner, &writable);
            Raw.X509AttributeFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.X509AttributeFfiResultVoidBoxPickyError>(resultPtr);
            Raw.X509AttributeFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string GetOid()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("MsCounterSign");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            IntPtr resultPtr = Raw.MsCounterSign.GetOid(_inner, &writeable);
            Raw.X509AttributeFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.X509AttributeFfiResultVoidBoxPickyError>(resultPtr);
            Raw.X509AttributeFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            string retVal = writeable.ToUnicode();
            writeable.Dispose();
            return retVal;
        }
    }

    /// <returns>
    /// A <c>SignedData</c> allocated on Rust side.
    /// </returns>
    public SignedData GetSignedData()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("MsCounterSign");
            }
            Raw.SignedData* retVal = Raw.MsCounterSign.GetSignedData(_inner);
            return new SignedData(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.MsCounterSign* AsFFI()
    {
        return _inner;
    }

    /// <summary>
    /// Destroys the underlying object immediately.
    /// </summary>
    public void Dispose()
    {
        unsafe
        {
            if (_inner == null)
            {
                return;
            }

            Raw.MsCounterSign.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~MsCounterSign()
    {
        Dispose();
    }
}
