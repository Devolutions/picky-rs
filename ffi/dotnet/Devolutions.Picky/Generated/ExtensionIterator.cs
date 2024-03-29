// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class ExtensionIterator: IDisposable
{
    private unsafe Raw.ExtensionIterator* _inner;

    /// <summary>
    /// Creates a managed <c>ExtensionIterator</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe ExtensionIterator(Raw.ExtensionIterator* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>Extension</c> allocated on Rust side.
    /// </returns>
    public Extension? Next()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionIterator");
            }
            Raw.Extension* retVal = Raw.ExtensionIterator.Next(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new Extension(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.ExtensionIterator* AsFFI()
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

            Raw.ExtensionIterator.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~ExtensionIterator()
    {
        Dispose();
    }
}
