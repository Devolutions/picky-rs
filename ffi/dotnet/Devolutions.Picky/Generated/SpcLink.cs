// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class SpcLink: IDisposable
{
    private unsafe Raw.SpcLink* _inner;

    public SpcString? File
    {
        get
        {
            return GetFile();
        }
    }

    public SpcSerializedObject? Moniker
    {
        get
        {
            return GetMoniker();
        }
    }

    public SpcLinkType Type
    {
        get
        {
            return GetType();
        }
    }

    public VecU8? Url
    {
        get
        {
            return GetUrl();
        }
    }

    /// <summary>
    /// Creates a managed <c>SpcLink</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe SpcLink(Raw.SpcLink* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>SpcLinkType</c> allocated on C# side.
    /// </returns>
    public SpcLinkType GetType()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SpcLink");
            }
            Raw.SpcLinkType retVal = Raw.SpcLink.GetType(_inner);
            return (SpcLinkType)retVal;
        }
    }

    /// <returns>
    /// A <c>VecU8</c> allocated on Rust side.
    /// </returns>
    public VecU8? GetUrl()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SpcLink");
            }
            Raw.VecU8* retVal = Raw.SpcLink.GetUrl(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new VecU8(retVal);
        }
    }

    /// <returns>
    /// A <c>SpcSerializedObject</c> allocated on Rust side.
    /// </returns>
    public SpcSerializedObject? GetMoniker()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SpcLink");
            }
            Raw.SpcSerializedObject* retVal = Raw.SpcLink.GetMoniker(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new SpcSerializedObject(retVal);
        }
    }

    /// <returns>
    /// A <c>SpcString</c> allocated on Rust side.
    /// </returns>
    public SpcString? GetFile()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SpcLink");
            }
            Raw.SpcString* retVal = Raw.SpcLink.GetFile(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new SpcString(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.SpcLink* AsFFI()
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

            Raw.SpcLink.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~SpcLink()
    {
        Dispose();
    }
}
