// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class BasicConstraints: IDisposable
{
    private unsafe Raw.BasicConstraints* _inner;

    public GetCaResult Ca
    {
        get
        {
            return GetCa();
        }
    }

    public U8? Pathlen
    {
        get
        {
            return GetPathlen();
        }
    }

    /// <summary>
    /// Creates a managed <c>BasicConstraints</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe BasicConstraints(Raw.BasicConstraints* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>GetCaResult</c> allocated on C# side.
    /// </returns>
    public GetCaResult GetCa()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("BasicConstraints");
            }
            Raw.GetCaResult retVal = Raw.BasicConstraints.GetCa(_inner);
            return (GetCaResult)retVal;
        }
    }

    /// <returns>
    /// A <c>U8</c> allocated on Rust side.
    /// </returns>
    public U8? GetPathlen()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("BasicConstraints");
            }
            Raw.U8* retVal = Raw.BasicConstraints.GetPathlen(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new U8(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.BasicConstraints* AsFFI()
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

            Raw.BasicConstraints.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~BasicConstraints()
    {
        Dispose();
    }
}
