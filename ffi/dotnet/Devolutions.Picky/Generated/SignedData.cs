// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class SignedData: IDisposable
{
    private unsafe Raw.SignedData* _inner;

    public CertificateChoicesIterator Certificates
    {
        get
        {
            return GetCertificates();
        }
    }

    public EncapsulatedContentInfo ContentInfo
    {
        get
        {
            return GetContentInfo();
        }
    }

    public RevocationInfoChoiceIterator? Crls
    {
        get
        {
            return GetCrls();
        }
    }

    public AlgorithmIdentifierIterator DigestAlgorithms
    {
        get
        {
            return GetDigestAlgorithms();
        }
    }

    public SignerInfoIterator SignersInfos
    {
        get
        {
            return GetSignersInfos();
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
    /// Creates a managed <c>SignedData</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe SignedData(Raw.SignedData* handle)
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
                throw new ObjectDisposedException("SignedData");
            }
            Raw.CmsVersion retVal = Raw.SignedData.GetVersion(_inner);
            return (CmsVersion)retVal;
        }
    }

    /// <returns>
    /// A <c>AlgorithmIdentifierIterator</c> allocated on Rust side.
    /// </returns>
    public AlgorithmIdentifierIterator GetDigestAlgorithms()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignedData");
            }
            Raw.AlgorithmIdentifierIterator* retVal = Raw.SignedData.GetDigestAlgorithms(_inner);
            return new AlgorithmIdentifierIterator(retVal);
        }
    }

    /// <returns>
    /// A <c>EncapsulatedContentInfo</c> allocated on Rust side.
    /// </returns>
    public EncapsulatedContentInfo GetContentInfo()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignedData");
            }
            Raw.EncapsulatedContentInfo* retVal = Raw.SignedData.GetContentInfo(_inner);
            return new EncapsulatedContentInfo(retVal);
        }
    }

    /// <returns>
    /// A <c>RevocationInfoChoiceIterator</c> allocated on Rust side.
    /// </returns>
    public RevocationInfoChoiceIterator? GetCrls()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignedData");
            }
            Raw.RevocationInfoChoiceIterator* retVal = Raw.SignedData.GetCrls(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new RevocationInfoChoiceIterator(retVal);
        }
    }

    /// <returns>
    /// A <c>CertificateChoicesIterator</c> allocated on Rust side.
    /// </returns>
    public CertificateChoicesIterator GetCertificates()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignedData");
            }
            Raw.CertificateChoicesIterator* retVal = Raw.SignedData.GetCertificates(_inner);
            return new CertificateChoicesIterator(retVal);
        }
    }

    /// <returns>
    /// A <c>SignerInfoIterator</c> allocated on Rust side.
    /// </returns>
    public SignerInfoIterator GetSignersInfos()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("SignedData");
            }
            Raw.SignerInfoIterator* retVal = Raw.SignedData.GetSignersInfos(_inner);
            return new SignerInfoIterator(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.SignedData* AsFFI()
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

            Raw.SignedData.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~SignedData()
    {
        Dispose();
    }
}
