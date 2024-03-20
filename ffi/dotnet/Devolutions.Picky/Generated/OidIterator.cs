// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class OidIterator: IDisposable
{
    private unsafe Raw.OidIterator* _inner;

    /// <summary>
    /// Creates a managed <c>OidIterator</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe OidIterator(Raw.OidIterator* handle)
    {
        _inner = handle;
    }

    /// <exception cref="PickyException"></exception>
    public void Next(DiplomatWriteable writable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("OidIterator");
            }
            IntPtr resultPtr = Raw.OidIterator.Next(_inner, &writable);
            Raw.X509ExtensionFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.X509ExtensionFfiResultVoidBoxPickyError>(resultPtr);
            Raw.X509ExtensionFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string Next()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("OidIterator");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            IntPtr resultPtr = Raw.OidIterator.Next(_inner, &writeable);
            Raw.X509ExtensionFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.X509ExtensionFfiResultVoidBoxPickyError>(resultPtr);
            Raw.X509ExtensionFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            string retVal = writeable.ToUnicode();
            writeable.Dispose();
            return retVal;
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.OidIterator* AsFFI()
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

            Raw.OidIterator.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~OidIterator()
    {
        Dispose();
    }
}
