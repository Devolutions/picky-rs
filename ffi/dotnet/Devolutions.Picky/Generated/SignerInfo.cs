// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class SignerInfo: IDisposable
{
    private unsafe Raw.SignerInfo* _inner;

    public AlgorithmIdentifier DigestAlgorithm
    {
        get
        {
            return GetDigestAlgorithm();
        }
    }

    public SingerIdentifier Sid
    {
        get
        {
            return GetSid();
        }
    }

    public VecU8 Signature
    {
        get
        {
            return GetSignature();
        }
    }

    public AlgorithmIdentifier SignatureAlgorithm
    {
        get
        {
            return GetSignatureAlgorithm();
        }
    }

    public AttributeIterator SignedAttributes
    {
        get
        {
            return GetSignedAttributes();
        }
    }

    public UnsignedAttributeIterator UnsignedAttributes
    {
        get
        {
            return GetUnsignedAttributes();
        }
    }

    public CmsVersion Version
    {
        get
        {
            return GetVersion();
        }
    }

    /// <summary>
    /// Creates a managed <c>SignerInfo</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe SignerInfo(Raw.SignerInfo* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>CmsVersion</c> allocated on C# side.
    /// </returns>
    public CmsVersion GetVersion()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignerInfo");
            }
            Raw.CmsVersion retVal = Raw.SignerInfo.GetVersion(_inner);
            return (CmsVersion)retVal;
        }
    }

    /// <returns>
    /// A <c>SingerIdentifier</c> allocated on Rust side.
    /// </returns>
    public SingerIdentifier GetSid()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignerInfo");
            }
            Raw.SingerIdentifier* retVal = Raw.SignerInfo.GetSid(_inner);
            return new SingerIdentifier(retVal);
        }
    }

    /// <returns>
    /// A <c>AlgorithmIdentifier</c> allocated on Rust side.
    /// </returns>
    public AlgorithmIdentifier GetDigestAlgorithm()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignerInfo");
            }
            Raw.AlgorithmIdentifier* retVal = Raw.SignerInfo.GetDigestAlgorithm(_inner);
            return new AlgorithmIdentifier(retVal);
        }
    }

    /// <returns>
    /// A <c>AlgorithmIdentifier</c> allocated on Rust side.
    /// </returns>
    public AlgorithmIdentifier GetSignatureAlgorithm()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignerInfo");
            }
            Raw.AlgorithmIdentifier* retVal = Raw.SignerInfo.GetSignatureAlgorithm(_inner);
            return new AlgorithmIdentifier(retVal);
        }
    }

    /// <returns>
    /// A <c>VecU8</c> allocated on Rust side.
    /// </returns>
    public VecU8 GetSignature()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignerInfo");
            }
            Raw.VecU8* retVal = Raw.SignerInfo.GetSignature(_inner);
            return new VecU8(retVal);
        }
    }

    /// <returns>
    /// A <c>UnsignedAttributeIterator</c> allocated on Rust side.
    /// </returns>
    public UnsignedAttributeIterator GetUnsignedAttributes()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignerInfo");
            }
            Raw.UnsignedAttributeIterator* retVal = Raw.SignerInfo.GetUnsignedAttributes(_inner);
            return new UnsignedAttributeIterator(retVal);
        }
    }

    /// <returns>
    /// A <c>AttributeIterator</c> allocated on Rust side.
    /// </returns>
    public AttributeIterator GetSignedAttributes()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignerInfo");
            }
            Raw.AttributeIterator* retVal = Raw.SignerInfo.GetSignedAttributes(_inner);
            return new AttributeIterator(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.SignerInfo* AsFFI()
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

            Raw.SignerInfo.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~SignerInfo()
    {
        Dispose();
    }
}
