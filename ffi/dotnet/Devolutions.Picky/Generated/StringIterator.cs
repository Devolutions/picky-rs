// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class StringIterator: IDisposable
{
    private unsafe Raw.StringIterator* _inner;

    /// <summary>
    /// Creates a managed <c>StringIterator</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe StringIterator(Raw.StringIterator* handle)
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
                throw new ObjectDisposedException("StringIterator");
            }
            Raw.UtilsFfiResultVoidBoxPickyError result = Raw.StringIterator.Next(_inner, &writable);
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
                throw new ObjectDisposedException("StringIterator");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            Raw.UtilsFfiResultVoidBoxPickyError result = Raw.StringIterator.Next(_inner, &writeable);
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
    public unsafe Raw.StringIterator* AsFFI()
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

            Raw.StringIterator.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~StringIterator()
    {
        Dispose();
    }
}
