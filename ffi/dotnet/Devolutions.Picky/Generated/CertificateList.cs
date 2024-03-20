// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class CertificateList: IDisposable
{
    private unsafe Raw.CertificateList* _inner;

    public AlgorithmIdentifier SignatureAlgorithm
    {
        get
        {
            return GetSignatureAlgorithm();
        }
    }

    public RsBuffer SignatureValue
    {
        get
        {
            return GetSignatureValue();
        }
    }

    public TbsCertList TbsCertList
    {
        get
        {
            return GetTbsCertList();
        }
    }

    /// <summary>
    /// Creates a managed <c>CertificateList</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe CertificateList(Raw.CertificateList* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>TbsCertList</c> allocated on Rust side.
    /// </returns>
    public TbsCertList GetTbsCertList()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("CertificateList");
            }
            Raw.TbsCertList* retVal = Raw.CertificateList.GetTbsCertList(_inner);
            return new TbsCertList(retVal);
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
                throw new ObjectDisposedException("CertificateList");
            }
            Raw.AlgorithmIdentifier* retVal = Raw.CertificateList.GetSignatureAlgorithm(_inner);
            return new AlgorithmIdentifier(retVal);
        }
    }

    /// <returns>
    /// A <c>RsBuffer</c> allocated on Rust side.
    /// </returns>
    public RsBuffer GetSignatureValue()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("CertificateList");
            }
            Raw.RsBuffer* retVal = Raw.CertificateList.GetSignatureValue(_inner);
            return new RsBuffer(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.CertificateList* AsFFI()
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

            Raw.CertificateList.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~CertificateList()
    {
        Dispose();
    }
}
