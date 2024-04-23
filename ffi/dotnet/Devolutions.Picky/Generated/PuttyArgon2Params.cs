// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

/// <summary>
/// Argon2 key derivation function parameters.
/// </summary>
public partial class PuttyArgon2Params: IDisposable
{
    private unsafe Raw.PuttyArgon2Params* _inner;

    /// <summary>
    /// Creates a managed <c>PuttyArgon2Params</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe PuttyArgon2Params(Raw.PuttyArgon2Params* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>PuttyArgon2Flavour</c> allocated on C# side.
    /// </returns>
    public PuttyArgon2Flavour Flavor()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PuttyArgon2Params");
            }
            Raw.PuttyArgon2Flavour retVal = Raw.PuttyArgon2Params.Flavor(_inner);
            return (PuttyArgon2Flavour)retVal;
        }
    }

    public uint Memory()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PuttyArgon2Params");
            }
            uint retVal = Raw.PuttyArgon2Params.Memory(_inner);
            return retVal;
        }
    }

    public uint Passes()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PuttyArgon2Params");
            }
            uint retVal = Raw.PuttyArgon2Params.Passes(_inner);
            return retVal;
        }
    }

    public uint Parallelism()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PuttyArgon2Params");
            }
            uint retVal = Raw.PuttyArgon2Params.Parallelism(_inner);
            return retVal;
        }
    }

    /// <returns>
    /// A <c>VecU8</c> allocated on Rust side.
    /// </returns>
    public VecU8 Salt()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PuttyArgon2Params");
            }
            Raw.VecU8* retVal = Raw.PuttyArgon2Params.Salt(_inner);
            return new VecU8(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.PuttyArgon2Params* AsFFI()
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

            Raw.PuttyArgon2Params.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~PuttyArgon2Params()
    {
        Dispose();
    }
}
