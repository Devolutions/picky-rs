// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

/// <summary>
/// Signed JSON Web Token object.
/// </summary>
/// <remarks>
/// This is a JWS (JSON Web Signature) structure with JWT claims contained in a JSON payload.
/// </remarks>
public partial class JwtSig: IDisposable
{
    private unsafe Raw.JwtSig* _inner;

    public string Claims
    {
        get
        {
            return GetClaims();
        }
    }

    public string ContentType
    {
        get
        {
            return GetContentType();
        }
    }

    public string Header
    {
        get
        {
            return GetHeader();
        }
    }

    /// <summary>
    /// Creates a managed <c>JwtSig</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe JwtSig(Raw.JwtSig* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>JwtSigBuilder</c> allocated on Rust side.
    /// </returns>
    public static JwtSigBuilder Builder()
    {
        unsafe
        {
            Raw.JwtSigBuilder* retVal = Raw.JwtSig.Builder();
            return new JwtSigBuilder(retVal);
        }
    }

    /// <summary>
    /// Returns the content type.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public void GetContentType(DiplomatWriteable writeable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSig");
            }
            IntPtr resultPtr = Raw.JwtSig.GetContentType(_inner, &writeable);
            Raw.JwtFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.JwtFfiResultVoidBoxPickyError>(resultPtr);
            Raw.JwtFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <summary>
    /// Returns the content type.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public string GetContentType()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSig");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            IntPtr resultPtr = Raw.JwtSig.GetContentType(_inner, &writeable);
            Raw.JwtFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.JwtFfiResultVoidBoxPickyError>(resultPtr);
            Raw.JwtFfiResultVoidBoxPickyError.Destroy(resultPtr);
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
    /// Returns the header as a JSON encoded payload.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public void GetHeader(DiplomatWriteable writeable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSig");
            }
            IntPtr resultPtr = Raw.JwtSig.GetHeader(_inner, &writeable);
            Raw.JwtFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.JwtFfiResultVoidBoxPickyError>(resultPtr);
            Raw.JwtFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <summary>
    /// Returns the header as a JSON encoded payload.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public string GetHeader()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSig");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            IntPtr resultPtr = Raw.JwtSig.GetHeader(_inner, &writeable);
            Raw.JwtFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.JwtFfiResultVoidBoxPickyError>(resultPtr);
            Raw.JwtFfiResultVoidBoxPickyError.Destroy(resultPtr);
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
    /// Returns the claims as a JSON encoded payload.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public void GetClaims(DiplomatWriteable writeable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSig");
            }
            IntPtr resultPtr = Raw.JwtSig.GetClaims(_inner, &writeable);
            Raw.JwtFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.JwtFfiResultVoidBoxPickyError>(resultPtr);
            Raw.JwtFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <summary>
    /// Returns the claims as a JSON encoded payload.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public string GetClaims()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSig");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            IntPtr resultPtr = Raw.JwtSig.GetClaims(_inner, &writeable);
            Raw.JwtFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.JwtFfiResultVoidBoxPickyError>(resultPtr);
            Raw.JwtFfiResultVoidBoxPickyError.Destroy(resultPtr);
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
    /// Decode JWT and check signature using provided public key.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>JwtSig</c> allocated on Rust side.
    /// </returns>
    public static JwtSig Decode(string encodedToken, PublicKey publicKey, JwtValidator validator)
    {
        unsafe
        {
            byte[] encodedTokenBuf = DiplomatUtils.StringToUtf8(encodedToken);
            nuint encodedTokenBufLength = (nuint)encodedTokenBuf.Length;
            Raw.PublicKey* publicKeyRaw;
            publicKeyRaw = publicKey.AsFFI();
            if (publicKeyRaw == null)
            {
                throw new ObjectDisposedException("PublicKey");
            }
            Raw.JwtValidator* validatorRaw;
            validatorRaw = validator.AsFFI();
            if (validatorRaw == null)
            {
                throw new ObjectDisposedException("JwtValidator");
            }
            fixed (byte* encodedTokenBufPtr = encodedTokenBuf)
            {
                IntPtr resultPtr = Raw.JwtSig.Decode(encodedTokenBufPtr, encodedTokenBufLength, publicKeyRaw, validatorRaw);
                Raw.JwtFfiResultBoxJwtSigBoxPickyError result = Marshal.PtrToStructure<Raw.JwtFfiResultBoxJwtSigBoxPickyError>(resultPtr);
                Raw.JwtFfiResultBoxJwtSigBoxPickyError.Destroy(resultPtr);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
                Raw.JwtSig* retVal = result.Ok;
                return new JwtSig(retVal);
            }
        }
    }

    /// <summary>
    /// Dangerous JWT decoding method. Signature isn't checked at all.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>JwtSig</c> allocated on Rust side.
    /// </returns>
    public static JwtSig DecodeDangerous(string encodedToken, JwtValidator validator)
    {
        unsafe
        {
            byte[] encodedTokenBuf = DiplomatUtils.StringToUtf8(encodedToken);
            nuint encodedTokenBufLength = (nuint)encodedTokenBuf.Length;
            Raw.JwtValidator* validatorRaw;
            validatorRaw = validator.AsFFI();
            if (validatorRaw == null)
            {
                throw new ObjectDisposedException("JwtValidator");
            }
            fixed (byte* encodedTokenBufPtr = encodedTokenBuf)
            {
                IntPtr resultPtr = Raw.JwtSig.DecodeDangerous(encodedTokenBufPtr, encodedTokenBufLength, validatorRaw);
                Raw.JwtFfiResultBoxJwtSigBoxPickyError result = Marshal.PtrToStructure<Raw.JwtFfiResultBoxJwtSigBoxPickyError>(resultPtr);
                Raw.JwtFfiResultBoxJwtSigBoxPickyError.Destroy(resultPtr);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
                Raw.JwtSig* retVal = result.Ok;
                return new JwtSig(retVal);
            }
        }
    }

    /// <summary>
    /// Encode using the given private key and returns the compact representation of this token.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public void Encode(PrivateKey key, DiplomatWriteable writeable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSig");
            }
            Raw.PrivateKey* keyRaw;
            keyRaw = key.AsFFI();
            if (keyRaw == null)
            {
                throw new ObjectDisposedException("PrivateKey");
            }
            IntPtr resultPtr = Raw.JwtSig.Encode(_inner, keyRaw, &writeable);
            Raw.JwtFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.JwtFfiResultVoidBoxPickyError>(resultPtr);
            Raw.JwtFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <summary>
    /// Encode using the given private key and returns the compact representation of this token.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public string Encode(PrivateKey key)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSig");
            }
            Raw.PrivateKey* keyRaw;
            keyRaw = key.AsFFI();
            if (keyRaw == null)
            {
                throw new ObjectDisposedException("PrivateKey");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            IntPtr resultPtr = Raw.JwtSig.Encode(_inner, keyRaw, &writeable);
            Raw.JwtFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.JwtFfiResultVoidBoxPickyError>(resultPtr);
            Raw.JwtFfiResultVoidBoxPickyError.Destroy(resultPtr);
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
    public unsafe Raw.JwtSig* AsFFI()
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

            Raw.JwtSig.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~JwtSig()
    {
        Dispose();
    }
}
