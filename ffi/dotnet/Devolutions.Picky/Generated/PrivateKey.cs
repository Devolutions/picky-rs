// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class PrivateKey: IDisposable
{
    private unsafe Raw.PrivateKey* _inner;

    public KeyKind Kind
    {
        get
        {
            return GetKind();
        }
    }

    /// <summary>
    /// Creates a managed <c>PrivateKey</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe PrivateKey(Raw.PrivateKey* handle)
    {
        _inner = handle;
    }

    /// <summary>
    /// Extracts private key from PEM object.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>PrivateKey</c> allocated on Rust side.
    /// </returns>
    public static PrivateKey FromPem(Pem pem)
    {
        unsafe
        {
            Raw.Pem* pemRaw;
            pemRaw = pem.AsFFI();
            if (pemRaw == null)
            {
                throw new ObjectDisposedException("Pem");
            }
            IntPtr resultPtr = Raw.PrivateKey.FromPem(pemRaw);
            Raw.KeyFfiResultBoxPrivateKeyBoxPickyError result = Marshal.PtrToStructure<Raw.KeyFfiResultBoxPrivateKeyBoxPickyError>(resultPtr);
            Raw.KeyFfiResultBoxPrivateKeyBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.PrivateKey* retVal = result.Ok;
            return new PrivateKey(retVal);
        }
    }

    /// <summary>
    /// Reads a private key from its PKCS8 storage.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>PrivateKey</c> allocated on Rust side.
    /// </returns>
    public static PrivateKey FromPkcs8(byte[] pkcs8)
    {
        unsafe
        {
            nuint pkcs8Length = (nuint)pkcs8.Length;
            fixed (byte* pkcs8Ptr = pkcs8)
            {
                IntPtr resultPtr = Raw.PrivateKey.FromPkcs8(pkcs8Ptr, pkcs8Length);
                Raw.KeyFfiResultBoxPrivateKeyBoxPickyError result = Marshal.PtrToStructure<Raw.KeyFfiResultBoxPrivateKeyBoxPickyError>(resultPtr);
                Raw.KeyFfiResultBoxPrivateKeyBoxPickyError.Destroy(resultPtr);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
                Raw.PrivateKey* retVal = result.Ok;
                return new PrivateKey(retVal);
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>PrivateKey</c> allocated on Rust side.
    /// </returns>
    public static PrivateKey FromPemStr(string pem)
    {
        unsafe
        {
            byte[] pemBuf = DiplomatUtils.StringToUtf8(pem);
            nuint pemBufLength = (nuint)pemBuf.Length;
            fixed (byte* pemBufPtr = pemBuf)
            {
                IntPtr resultPtr = Raw.PrivateKey.FromPemStr(pemBufPtr, pemBufLength);
                Raw.KeyFfiResultBoxPrivateKeyBoxPickyError result = Marshal.PtrToStructure<Raw.KeyFfiResultBoxPrivateKeyBoxPickyError>(resultPtr);
                Raw.KeyFfiResultBoxPrivateKeyBoxPickyError.Destroy(resultPtr);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
                Raw.PrivateKey* retVal = result.Ok;
                return new PrivateKey(retVal);
            }
        }
    }

    /// <summary>
    /// Generates a new RSA private key.
    /// </summary>
    /// <remarks>
    /// This is slow in debug builds.
    /// </remarks>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>PrivateKey</c> allocated on Rust side.
    /// </returns>
    public static PrivateKey GenerateRsa(nuint bits)
    {
        unsafe
        {
            IntPtr resultPtr = Raw.PrivateKey.GenerateRsa(bits);
            Raw.KeyFfiResultBoxPrivateKeyBoxPickyError result = Marshal.PtrToStructure<Raw.KeyFfiResultBoxPrivateKeyBoxPickyError>(resultPtr);
            Raw.KeyFfiResultBoxPrivateKeyBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.PrivateKey* retVal = result.Ok;
            return new PrivateKey(retVal);
        }
    }

    /// <summary>
    /// Generates a new EC private key.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>PrivateKey</c> allocated on Rust side.
    /// </returns>
    public static PrivateKey GenerateEc(EcCurve curve)
    {
        unsafe
        {
            Raw.EcCurve curveRaw;
            curveRaw = (Raw.EcCurve)curve;
            IntPtr resultPtr = Raw.PrivateKey.GenerateEc(curveRaw);
            Raw.KeyFfiResultBoxPrivateKeyBoxPickyError result = Marshal.PtrToStructure<Raw.KeyFfiResultBoxPrivateKeyBoxPickyError>(resultPtr);
            Raw.KeyFfiResultBoxPrivateKeyBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.PrivateKey* retVal = result.Ok;
            return new PrivateKey(retVal);
        }
    }

    /// <summary>
    /// Generates new ed key pair with specified supported algorithm.
    /// </summary>
    /// <remarks>
    /// `write_public_key` specifies whether to include public key in the private key file.
    /// Note that OpenSSL does not support ed keys with public key included.
    /// </remarks>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>PrivateKey</c> allocated on Rust side.
    /// </returns>
    public static PrivateKey GenerateEd(EdAlgorithm algorithm, bool writePublicKey)
    {
        unsafe
        {
            Raw.EdAlgorithm algorithmRaw;
            algorithmRaw = (Raw.EdAlgorithm)algorithm;
            IntPtr resultPtr = Raw.PrivateKey.GenerateEd(algorithmRaw, writePublicKey);
            Raw.KeyFfiResultBoxPrivateKeyBoxPickyError result = Marshal.PtrToStructure<Raw.KeyFfiResultBoxPrivateKeyBoxPickyError>(resultPtr);
            Raw.KeyFfiResultBoxPrivateKeyBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.PrivateKey* retVal = result.Ok;
            return new PrivateKey(retVal);
        }
    }

    /// <summary>
    /// Exports the private key into a PEM object
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>Pem</c> allocated on Rust side.
    /// </returns>
    public Pem ToPem()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PrivateKey");
            }
            IntPtr resultPtr = Raw.PrivateKey.ToPem(_inner);
            Raw.KeyFfiResultBoxPemBoxPickyError result = Marshal.PtrToStructure<Raw.KeyFfiResultBoxPemBoxPickyError>(resultPtr);
            Raw.KeyFfiResultBoxPemBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.Pem* retVal = result.Ok;
            return new Pem(retVal);
        }
    }

    /// <summary>
    /// Extracts the public part of this private key
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>PublicKey</c> allocated on Rust side.
    /// </returns>
    public PublicKey ToPublicKey()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PrivateKey");
            }
            IntPtr resultPtr = Raw.PrivateKey.ToPublicKey(_inner);
            Raw.KeyFfiResultBoxPublicKeyBoxPickyError result = Marshal.PtrToStructure<Raw.KeyFfiResultBoxPublicKeyBoxPickyError>(resultPtr);
            Raw.KeyFfiResultBoxPublicKeyBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.PublicKey* retVal = result.Ok;
            return new PublicKey(retVal);
        }
    }

    /// <summary>
    /// Retrieves the key kind for this private key.
    /// </summary>
    /// <returns>
    /// A <c>KeyKind</c> allocated on C# side.
    /// </returns>
    public KeyKind GetKind()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("PrivateKey");
            }
            Raw.KeyKind retVal = Raw.PrivateKey.GetKind(_inner);
            return (KeyKind)retVal;
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.PrivateKey* AsFFI()
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

            Raw.PrivateKey.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~PrivateKey()
    {
        Dispose();
    }
}
