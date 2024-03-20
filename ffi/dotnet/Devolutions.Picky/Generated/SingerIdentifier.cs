// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class SingerIdentifier: IDisposable
{
    private unsafe Raw.SingerIdentifier* _inner;

    public IssuerAndSerialNumber? IssureAndSerialNumber
    {
        get
        {
            return GetIssureAndSerialNumber();
        }
    }

    public RsBuffer? SubjectKeyIdentifier
    {
        get
        {
            return GetSubjectKeyIdentifier();
        }
    }

    /// <summary>
    /// Creates a managed <c>SingerIdentifier</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe SingerIdentifier(Raw.SingerIdentifier* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>IssuerAndSerialNumber</c> allocated on Rust side.
    /// </returns>
    public IssuerAndSerialNumber? GetIssureAndSerialNumber()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SingerIdentifier");
            }
            Raw.IssuerAndSerialNumber* retVal = Raw.SingerIdentifier.GetIssureAndSerialNumber(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new IssuerAndSerialNumber(retVal);
        }
    }

    /// <returns>
    /// A <c>RsBuffer</c> allocated on Rust side.
    /// </returns>
    public RsBuffer? GetSubjectKeyIdentifier()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SingerIdentifier");
            }
            Raw.RsBuffer* retVal = Raw.SingerIdentifier.GetSubjectKeyIdentifier(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new RsBuffer(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.SingerIdentifier* AsFFI()
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

            Raw.SingerIdentifier.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~SingerIdentifier()
    {
        Dispose();
    }
}
