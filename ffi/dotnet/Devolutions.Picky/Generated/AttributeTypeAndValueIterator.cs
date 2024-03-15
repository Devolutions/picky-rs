// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class AttributeTypeAndValueIterator: IDisposable
{
    private unsafe Raw.AttributeTypeAndValueIterator* _inner;

    /// <summary>
    /// Creates a managed <c>AttributeTypeAndValueIterator</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe AttributeTypeAndValueIterator(Raw.AttributeTypeAndValueIterator* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>AttributeTypeAndValue</c> allocated on Rust side.
    /// </returns>
    public AttributeTypeAndValue? Next()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("AttributeTypeAndValueIterator");
            }
            Raw.AttributeTypeAndValue* retVal = Raw.AttributeTypeAndValueIterator.Next(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new AttributeTypeAndValue(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.AttributeTypeAndValueIterator* AsFFI()
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

            Raw.AttributeTypeAndValueIterator.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~AttributeTypeAndValueIterator()
    {
        Dispose();
    }
}
