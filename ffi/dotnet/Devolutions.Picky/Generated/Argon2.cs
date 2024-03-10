// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class Argon2: IDisposable
{
    private unsafe Raw.Argon2* _inner;

    /// <summary>
    /// Creates a managed <c>Argon2</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe Argon2(Raw.Argon2* handle)
    {
        _inner = handle;
    }

    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>Argon2</c> allocated on Rust side.
    /// </returns>
    public static Argon2 New(Argon2Algorithm algorithm, Argon2Params parameters)
    {
        unsafe
        {
            Raw.Argon2Algorithm algorithmRaw;
            algorithmRaw = (Raw.Argon2Algorithm)algorithm;
            Raw.Argon2Params* parametersRaw;
            parametersRaw = parameters.AsFFI();
            if (parametersRaw == null)
            {
                throw new ObjectDisposedException("Argon2Params");
            }
            Raw.Argon2FfiResultBoxArgon2BoxPickyError result = Raw.Argon2.New(algorithmRaw, parametersRaw);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.Argon2* retVal = result.Ok;
            return new Argon2(retVal);
        }
    }

    /// <exception cref="PickyException"></exception>
    public void HashPassword(string password, DiplomatWriteable writeable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Argon2");
            }
            byte[] passwordBuf = DiplomatUtils.StringToUtf8(password);
            nuint passwordBufLength = (nuint)passwordBuf.Length;
            fixed (byte* passwordBufPtr = passwordBuf)
            {
                Raw.Argon2FfiResultVoidBoxPickyError result = Raw.Argon2.HashPassword(_inner, passwordBufPtr, passwordBufLength, &writeable);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string HashPassword(string password)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Argon2");
            }
            byte[] passwordBuf = DiplomatUtils.StringToUtf8(password);
            nuint passwordBufLength = (nuint)passwordBuf.Length;
            fixed (byte* passwordBufPtr = passwordBuf)
            {
                DiplomatWriteable writeable = new DiplomatWriteable();
                Raw.Argon2FfiResultVoidBoxPickyError result = Raw.Argon2.HashPassword(_inner, passwordBufPtr, passwordBufLength, &writeable);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
                string retVal = writeable.ToUnicode();
                writeable.Dispose();
                return retVal;
            }
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.Argon2* AsFFI()
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

            Raw.Argon2.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~Argon2()
    {
        Dispose();
    }
}
