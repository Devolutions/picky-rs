// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class GeneralNameIterator: IDisposable
{
    private unsafe Raw.GeneralNameIterator* _inner;

    /// <summary>
    /// Creates a managed <c>GeneralNameIterator</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe GeneralNameIterator(Raw.GeneralNameIterator* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>GeneralName</c> allocated on Rust side.
    /// </returns>
    public GeneralName? Next()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralNameIterator");
            }
            Raw.GeneralName* retVal = Raw.GeneralNameIterator.Next(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new GeneralName(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.GeneralNameIterator* AsFFI()
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

            Raw.GeneralNameIterator.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~GeneralNameIterator()
    {
        Dispose();
    }
}
