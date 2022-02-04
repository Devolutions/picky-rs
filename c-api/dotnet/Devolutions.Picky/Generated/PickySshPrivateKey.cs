// Automatically generated by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

/// <summary>
/// SSH Private Key.
/// </summary>
public partial class PickySshPrivateKey: IDisposable
{
    private unsafe Raw.PickySshPrivateKey* _inner;

    public string CipherName
    {
        get
        {
            return GetCipherName();
        }
    }

    public string Comment
    {
        get
        {
            return GetComment();
        }
    }

    /// <summary>
    /// Creates a managed <c>PickySshPrivateKey</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// </remarks>
    /// <remarks>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe PickySshPrivateKey(Raw.PickySshPrivateKey* handle)
    {
        _inner = handle;
    }

    /// <summary>
    /// Generates a new SSH RSA Private Key.
    /// </summary>
    /// <remarks>
    /// No passphrase is set if `passphrase` is empty.
    /// </remarks>
    /// <remarks>
    /// No comment is set if `comment` is empty.
    /// </remarks>
    /// <remarks>
    /// This is slow in debug builds.
    /// </remarks>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>PickySshPrivateKey</c> allocated on Rust side.
    /// </returns>
    public static PickySshPrivateKey GenerateRsa(nuint bits, string passphrase, string comment)
    {
        unsafe
        {
            byte[] passphraseBuf = DiplomatUtils.StringToUtf8(passphrase);
            byte[] commentBuf = DiplomatUtils.StringToUtf8(comment);
            nuint passphraseBufLength = (nuint)passphraseBuf.Length;
            nuint commentBufLength = (nuint)commentBuf.Length;
            fixed (byte* passphraseBufPtr = passphraseBuf)
            {
                fixed (byte* commentBufPtr = commentBuf)
                {
                    Raw.SshFfiResultBoxPickySshPrivateKeyBoxPickyError result = Raw.PickySshPrivateKey.GenerateRsa(bits, passphraseBufPtr, passphraseBufLength, commentBufPtr, commentBufLength);
                    if (!result.isOk)
                    {
                        throw new PickyException(new PickyError(result.Err));
                    }
                    Raw.PickySshPrivateKey* retVal = result.Ok;
                    return new PickySshPrivateKey(retVal);
                }
            }
        }
    }

    /// <summary>
    /// Extracts SSH Private Key from PEM object.
    /// </summary>
    /// <remarks>
    /// No passphrase is set if `passphrase` is empty.
    /// </remarks>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>PickySshPrivateKey</c> allocated on Rust side.
    /// </returns>
    public static PickySshPrivateKey FromPem(PickyPem pem, string passphrase)
    {
        unsafe
        {
            byte[] passphraseBuf = DiplomatUtils.StringToUtf8(passphrase);
            nuint passphraseBufLength = (nuint)passphraseBuf.Length;
            Raw.PickyPem* pemRaw;
            pemRaw = pem.AsFFI();
            if (pemRaw == null)
            {
                throw new ObjectDisposedException("PickyPem");
            }
            fixed (byte* passphraseBufPtr = passphraseBuf)
            {
                Raw.SshFfiResultBoxPickySshPrivateKeyBoxPickyError result = Raw.PickySshPrivateKey.FromPem(pemRaw, passphraseBufPtr, passphraseBufLength);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
                Raw.PickySshPrivateKey* retVal = result.Ok;
                return new PickySshPrivateKey(retVal);
            }
        }
    }

    /// <returns>
    /// A <c>PickySshPrivateKey</c> allocated on Rust side.
    /// </returns>
    public static PickySshPrivateKey FromPrivateKey(PickyPrivateKey key)
    {
        unsafe
        {
            Raw.PickyPrivateKey* keyRaw;
            keyRaw = key.AsFFI();
            if (keyRaw == null)
            {
                throw new ObjectDisposedException("PickyPrivateKey");
            }
            Raw.PickySshPrivateKey* retVal = Raw.PickySshPrivateKey.FromPrivateKey(keyRaw);
            return new PickySshPrivateKey(retVal);
        }
    }

    /// <summary>
    /// Exports the SSH Private Key into a PEM object
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>PickyPem</c> allocated on Rust side.
    /// </returns>
    public PickyPem ToPem()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PickySshPrivateKey");
            }
            Raw.SshFfiResultBoxPickyPemBoxPickyError result = Raw.PickySshPrivateKey.ToPem(_inner);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.PickyPem* retVal = result.Ok;
            return new PickyPem(retVal);
        }
    }

    /// <summary>
    /// Returns the SSH Private Key string representation.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public void ToRepr(DiplomatWriteable writeable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PickySshPrivateKey");
            }
            Raw.SshFfiResultVoidBoxPickyError result = Raw.PickySshPrivateKey.ToRepr(_inner, &writeable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <summary>
    /// Returns the SSH Private Key string representation.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public string ToRepr()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PickySshPrivateKey");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            Raw.SshFfiResultVoidBoxPickyError result = Raw.PickySshPrivateKey.ToRepr(_inner, &writeable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            string retVal = writeable.ToUnicode();
            writeable.Dispose();
            return retVal;
        }
    }

    /// <exception cref="PickyException"></exception>
    public void GetCipherName(DiplomatWriteable writeable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PickySshPrivateKey");
            }
            Raw.SshFfiResultVoidBoxPickyError result = Raw.PickySshPrivateKey.GetCipherName(_inner, &writeable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string GetCipherName()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PickySshPrivateKey");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            Raw.SshFfiResultVoidBoxPickyError result = Raw.PickySshPrivateKey.GetCipherName(_inner, &writeable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            string retVal = writeable.ToUnicode();
            writeable.Dispose();
            return retVal;
        }
    }

    /// <exception cref="PickyException"></exception>
    public void GetComment(DiplomatWriteable writeable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PickySshPrivateKey");
            }
            Raw.SshFfiResultVoidBoxPickyError result = Raw.PickySshPrivateKey.GetComment(_inner, &writeable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string GetComment()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PickySshPrivateKey");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            Raw.SshFfiResultVoidBoxPickyError result = Raw.PickySshPrivateKey.GetComment(_inner, &writeable);
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
    /// Extracts the public part of this private key
    /// </summary>
    /// <returns>
    /// A <c>PickySshPublicKey</c> allocated on Rust side.
    /// </returns>
    public PickySshPublicKey ToPublicKey()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PickySshPrivateKey");
            }
            Raw.PickySshPublicKey* retVal = Raw.PickySshPrivateKey.ToPublicKey(_inner);
            return new PickySshPublicKey(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.PickySshPrivateKey* AsFFI()
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

            Raw.PickySshPrivateKey.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~PickySshPrivateKey()
    {
        Dispose();
    }
}
