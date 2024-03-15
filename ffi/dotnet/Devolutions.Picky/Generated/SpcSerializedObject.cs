// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class SpcSerializedObject: IDisposable
{
    private unsafe Raw.SpcSerializedObject* _inner;

    public Buffer ClassId
    {
        get
        {
            return GetClassId();
        }
    }

    public Buffer ObjectId
    {
        get
        {
            return GetObjectId();
        }
    }

    /// <summary>
    /// Creates a managed <c>SpcSerializedObject</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe SpcSerializedObject(Raw.SpcSerializedObject* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>Buffer</c> allocated on Rust side.
    /// </returns>
    public Buffer GetClassId()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SpcSerializedObject");
            }
            Raw.Buffer* retVal = Raw.SpcSerializedObject.GetClassId(_inner);
            return new Buffer(retVal);
        }
    }

    /// <returns>
    /// A <c>Buffer</c> allocated on Rust side.
    /// </returns>
    public Buffer GetObjectId()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SpcSerializedObject");
            }
            Raw.Buffer* retVal = Raw.SpcSerializedObject.GetObjectId(_inner);
            return new Buffer(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.SpcSerializedObject* AsFFI()
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

            Raw.SpcSerializedObject.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~SpcSerializedObject()
    {
        Dispose();
    }
}
