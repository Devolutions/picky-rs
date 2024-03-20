// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class DirectoryString: IDisposable
{
    private unsafe Raw.DirectoryString* _inner;

    public RsBuffer AsBytes
    {
        get
        {
            return GetAsBytes();
        }
    }

    public string AsString
    {
        get
        {
            return GetAsString();
        }
    }

    public DirectoryStringType Type
    {
        get
        {
            return GetType();
        }
    }

    /// <summary>
    /// Creates a managed <c>DirectoryString</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe DirectoryString(Raw.DirectoryString* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>DirectoryStringType</c> allocated on C# side.
    /// </returns>
    public DirectoryStringType GetType()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("DirectoryString");
            }
            Raw.DirectoryStringType retVal = Raw.DirectoryString.GetType(_inner);
            return (DirectoryStringType)retVal;
        }
    }

    /// <exception cref="PickyException"></exception>
    public void GetAsString(DiplomatWriteable writable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("DirectoryString");
            }
            IntPtr resultPtr = Raw.DirectoryString.GetAsString(_inner, &writable);
            Raw.X509StringFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.X509StringFfiResultVoidBoxPickyError>(resultPtr);
            Raw.X509StringFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string GetAsString()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("DirectoryString");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            IntPtr resultPtr = Raw.DirectoryString.GetAsString(_inner, &writeable);
            Raw.X509StringFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.X509StringFfiResultVoidBoxPickyError>(resultPtr);
            Raw.X509StringFfiResultVoidBoxPickyError.Destroy(resultPtr);
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
    /// A <c>RsBuffer</c> allocated on Rust side.
    /// </returns>
    public RsBuffer GetAsBytes()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("DirectoryString");
            }
            Raw.RsBuffer* retVal = Raw.DirectoryString.GetAsBytes(_inner);
            return new RsBuffer(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.DirectoryString* AsFFI()
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

            Raw.DirectoryString.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~DirectoryString()
    {
        Dispose();
    }
}
