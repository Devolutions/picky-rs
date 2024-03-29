// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class AuthenticodeSignature: IDisposable
{
    private unsafe Raw.AuthenticodeSignature* _inner;

    /// <summary>
    /// Creates a managed <c>AuthenticodeSignature</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe AuthenticodeSignature(Raw.AuthenticodeSignature* handle)
    {
        _inner = handle;
    }

    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>AuthenticodeSignature</c> allocated on Rust side.
    /// </returns>
    public static AuthenticodeSignature New(Pkcs7 pkcs7, VecU8 fileHash, ShaVariant hashAlgorithm, PrivateKey privateKey, RsString? programName)
    {
        unsafe
        {
            Raw.Pkcs7* pkcs7Raw;
            pkcs7Raw = pkcs7.AsFFI();
            if (pkcs7Raw == null)
            {
                throw new ObjectDisposedException("Pkcs7");
            }
            Raw.VecU8* fileHashRaw;
            fileHashRaw = fileHash.AsFFI();
            if (fileHashRaw == null)
            {
                throw new ObjectDisposedException("VecU8");
            }
            Raw.ShaVariant hashAlgorithmRaw;
            hashAlgorithmRaw = (Raw.ShaVariant)hashAlgorithm;
            Raw.PrivateKey* privateKeyRaw;
            privateKeyRaw = privateKey.AsFFI();
            if (privateKeyRaw == null)
            {
                throw new ObjectDisposedException("PrivateKey");
            }
            Raw.RsString* programNameRaw;
            if (programName == null)
            {
                programNameRaw = null;
            }
            else
            {
                programNameRaw = programName.AsFFI();
                if (programNameRaw == null)
                {
                    throw new ObjectDisposedException("RsString");
                }
            }
            IntPtr resultPtr = Raw.AuthenticodeSignature.New(pkcs7Raw, fileHashRaw, hashAlgorithmRaw, privateKeyRaw, programNameRaw);
            Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError result = Marshal.PtrToStructure<Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError>(resultPtr);
            Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.AuthenticodeSignature* retVal = result.Ok;
            return new AuthenticodeSignature(retVal);
        }
    }

    /// <exception cref="PickyException"></exception>
    public void Timestamp(AuthenticodeTimestamper timestamper, HashAlgorithm hashAlgo)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("AuthenticodeSignature");
            }
            Raw.AuthenticodeTimestamper* timestamperRaw;
            timestamperRaw = timestamper.AsFFI();
            if (timestamperRaw == null)
            {
                throw new ObjectDisposedException("AuthenticodeTimestamper");
            }
            Raw.HashAlgorithm hashAlgoRaw;
            hashAlgoRaw = (Raw.HashAlgorithm)hashAlgo;
            IntPtr resultPtr = Raw.AuthenticodeSignature.Timestamp(_inner, timestamperRaw, hashAlgoRaw);
            Raw.X509AuthenticodeFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.X509AuthenticodeFfiResultVoidBoxPickyError>(resultPtr);
            Raw.X509AuthenticodeFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>AuthenticodeSignature</c> allocated on Rust side.
    /// </returns>
    public static AuthenticodeSignature FromDer(VecU8 der)
    {
        unsafe
        {
            Raw.VecU8* derRaw;
            derRaw = der.AsFFI();
            if (derRaw == null)
            {
                throw new ObjectDisposedException("VecU8");
            }
            IntPtr resultPtr = Raw.AuthenticodeSignature.FromDer(derRaw);
            Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError result = Marshal.PtrToStructure<Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError>(resultPtr);
            Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.AuthenticodeSignature* retVal = result.Ok;
            return new AuthenticodeSignature(retVal);
        }
    }

    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>AuthenticodeSignature</c> allocated on Rust side.
    /// </returns>
    public static AuthenticodeSignature FromPem(Pem pem)
    {
        unsafe
        {
            Raw.Pem* pemRaw;
            pemRaw = pem.AsFFI();
            if (pemRaw == null)
            {
                throw new ObjectDisposedException("Pem");
            }
            IntPtr resultPtr = Raw.AuthenticodeSignature.FromPem(pemRaw);
            Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError result = Marshal.PtrToStructure<Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError>(resultPtr);
            Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.AuthenticodeSignature* retVal = result.Ok;
            return new AuthenticodeSignature(retVal);
        }
    }

    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>AuthenticodeSignature</c> allocated on Rust side.
    /// </returns>
    public static AuthenticodeSignature FromPemStr(string pem)
    {
        unsafe
        {
            byte[] pemBuf = DiplomatUtils.StringToUtf8(pem);
            nuint pemBufLength = (nuint)pemBuf.Length;
            fixed (byte* pemBufPtr = pemBuf)
            {
                IntPtr resultPtr = Raw.AuthenticodeSignature.FromPemStr(pemBufPtr, pemBufLength);
                Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError result = Marshal.PtrToStructure<Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError>(resultPtr);
                Raw.X509AuthenticodeFfiResultBoxAuthenticodeSignatureBoxPickyError.Destroy(resultPtr);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
                Raw.AuthenticodeSignature* retVal = result.Ok;
                return new AuthenticodeSignature(retVal);
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>VecU8</c> allocated on Rust side.
    /// </returns>
    public VecU8 ToDer()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("AuthenticodeSignature");
            }
            IntPtr resultPtr = Raw.AuthenticodeSignature.ToDer(_inner);
            Raw.X509AuthenticodeFfiResultBoxVecU8BoxPickyError result = Marshal.PtrToStructure<Raw.X509AuthenticodeFfiResultBoxVecU8BoxPickyError>(resultPtr);
            Raw.X509AuthenticodeFfiResultBoxVecU8BoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.VecU8* retVal = result.Ok;
            return new VecU8(retVal);
        }
    }

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
                throw new ObjectDisposedException("AuthenticodeSignature");
            }
            IntPtr resultPtr = Raw.AuthenticodeSignature.ToPem(_inner);
            Raw.X509AuthenticodeFfiResultBoxPemBoxPickyError result = Marshal.PtrToStructure<Raw.X509AuthenticodeFfiResultBoxPemBoxPickyError>(resultPtr);
            Raw.X509AuthenticodeFfiResultBoxPemBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.Pem* retVal = result.Ok;
            return new Pem(retVal);
        }
    }

    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>Cert</c> allocated on Rust side.
    /// </returns>
    public Cert SigningCertificate(CertIterator cert)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("AuthenticodeSignature");
            }
            Raw.CertIterator* certRaw;
            certRaw = cert.AsFFI();
            if (certRaw == null)
            {
                throw new ObjectDisposedException("CertIterator");
            }
            IntPtr resultPtr = Raw.AuthenticodeSignature.SigningCertificate(_inner, certRaw);
            Raw.X509AuthenticodeFfiResultBoxCertBoxPickyError result = Marshal.PtrToStructure<Raw.X509AuthenticodeFfiResultBoxCertBoxPickyError>(resultPtr);
            Raw.X509AuthenticodeFfiResultBoxCertBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            Raw.Cert* retVal = result.Ok;
            return new Cert(retVal);
        }
    }

    /// <returns>
    /// A <c>AuthenticodeValidator</c> allocated on Rust side.
    /// </returns>
    public AuthenticodeValidator AuthenticodeVerifier()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("AuthenticodeSignature");
            }
            Raw.AuthenticodeValidator* retVal = Raw.AuthenticodeSignature.AuthenticodeVerifier(_inner);
            return new AuthenticodeValidator(retVal);
        }
    }

    /// <returns>
    /// A <c>VecU8</c> allocated on Rust side.
    /// </returns>
    public VecU8? FileHash()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("AuthenticodeSignature");
            }
            Raw.VecU8* retVal = Raw.AuthenticodeSignature.FileHash(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new VecU8(retVal);
        }
    }

    /// <returns>
    /// A <c>AttributeIterator</c> allocated on Rust side.
    /// </returns>
    public AttributeIterator AuthenticateAttributes()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("AuthenticodeSignature");
            }
            Raw.AttributeIterator* retVal = Raw.AuthenticodeSignature.AuthenticateAttributes(_inner);
            return new AttributeIterator(retVal);
        }
    }

    /// <returns>
    /// A <c>UnsignedAttributeIterator</c> allocated on Rust side.
    /// </returns>
    public UnsignedAttributeIterator UnauthenticatedAttributes()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("AuthenticodeSignature");
            }
            Raw.UnsignedAttributeIterator* retVal = Raw.AuthenticodeSignature.UnauthenticatedAttributes(_inner);
            return new UnsignedAttributeIterator(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.AuthenticodeSignature* AsFFI()
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

            Raw.AuthenticodeSignature.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~AuthenticodeSignature()
    {
        Dispose();
    }
}
