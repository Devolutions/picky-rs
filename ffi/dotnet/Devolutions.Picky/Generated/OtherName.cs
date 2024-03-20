// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class OtherName: IDisposable
{
    private unsafe Raw.OtherName* _inner;

    public string TypeId
    {
        get
        {
            return GetTypeId();
        }
    }

    public Buffer Value
    {
        get
        {
            return GetValue();
        }
    }

    /// <summary>
    /// Creates a managed <c>OtherName</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe OtherName(Raw.OtherName* handle)
    {
        _inner = handle;
    }

    /// <exception cref="PickyException"></exception>
    public void GetTypeId(DiplomatWriteable writable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("OtherName");
            }
            IntPtr resultPtr = Raw.OtherName.GetTypeId(_inner, &writable);
            Raw.X509NameFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.X509NameFfiResultVoidBoxPickyError>(resultPtr);
            Raw.X509NameFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string GetTypeId()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("OtherName");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            IntPtr resultPtr = Raw.OtherName.GetTypeId(_inner, &writeable);
            Raw.X509NameFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.X509NameFfiResultVoidBoxPickyError>(resultPtr);
            Raw.X509NameFfiResultVoidBoxPickyError.Destroy(resultPtr);
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
    /// A <c>Buffer</c> allocated on Rust side.
    /// </returns>
    public Buffer GetValue()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("OtherName");
            }
            Raw.Buffer* retVal = Raw.OtherName.GetValue(_inner);
            return new Buffer(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.OtherName* AsFFI()
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

            Raw.OtherName.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~OtherName()
    {
        Dispose();
    }
}
