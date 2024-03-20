// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class ExtensionView: IDisposable
{
    private unsafe Raw.ExtensionView* _inner;

    public ExtensionViewType Type
    {
        get
        {
            return GetType();
        }
    }

    /// <summary>
    /// Creates a managed <c>ExtensionView</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe ExtensionView(Raw.ExtensionView* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>ExtensionViewType</c> allocated on C# side.
    /// </returns>
    public ExtensionViewType GetType()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionView");
            }
            Raw.ExtensionViewType retVal = Raw.ExtensionView.GetType(_inner);
            return (ExtensionViewType)retVal;
        }
    }

    /// <returns>
    /// A <c>AuthorityKeyIdentifier</c> allocated on Rust side.
    /// </returns>
    public AuthorityKeyIdentifier? ToAuthorityKeyIdentifier()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionView");
            }
            Raw.AuthorityKeyIdentifier* retVal = Raw.ExtensionView.ToAuthorityKeyIdentifier(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new AuthorityKeyIdentifier(retVal);
        }
    }

    /// <returns>
    /// A <c>RsBuffer</c> allocated on Rust side.
    /// </returns>
    public RsBuffer? ToSubjectKeyIdentifier()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionView");
            }
            Raw.RsBuffer* retVal = Raw.ExtensionView.ToSubjectKeyIdentifier(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new RsBuffer(retVal);
        }
    }

    /// <returns>
    /// A <c>RsBuffer</c> allocated on Rust side.
    /// </returns>
    public RsBuffer? ToKeyUsage()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionView");
            }
            Raw.RsBuffer* retVal = Raw.ExtensionView.ToKeyUsage(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new RsBuffer(retVal);
        }
    }

    /// <returns>
    /// A <c>GeneralNameIterator</c> allocated on Rust side.
    /// </returns>
    public GeneralNameIterator? ToSubjectAltName()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionView");
            }
            Raw.GeneralNameIterator* retVal = Raw.ExtensionView.ToSubjectAltName(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new GeneralNameIterator(retVal);
        }
    }

    /// <returns>
    /// A <c>GeneralNameIterator</c> allocated on Rust side.
    /// </returns>
    public GeneralNameIterator? ToIssuerAltName()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionView");
            }
            Raw.GeneralNameIterator* retVal = Raw.ExtensionView.ToIssuerAltName(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new GeneralNameIterator(retVal);
        }
    }

    /// <returns>
    /// A <c>BasicConstraints</c> allocated on Rust side.
    /// </returns>
    public BasicConstraints? ToBasicConstraints()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionView");
            }
            Raw.BasicConstraints* retVal = Raw.ExtensionView.ToBasicConstraints(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new BasicConstraints(retVal);
        }
    }

    /// <returns>
    /// A <c>OidIterator</c> allocated on Rust side.
    /// </returns>
    public OidIterator? ToExtendedKeyUsage()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionView");
            }
            Raw.OidIterator* retVal = Raw.ExtensionView.ToExtendedKeyUsage(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new OidIterator(retVal);
        }
    }

    /// <returns>
    /// A <c>RsBuffer</c> allocated on Rust side.
    /// </returns>
    public RsBuffer? ToGeneric()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionView");
            }
            Raw.RsBuffer* retVal = Raw.ExtensionView.ToGeneric(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new RsBuffer(retVal);
        }
    }

    /// <returns>
    /// A <c>RsBuffer</c> allocated on Rust side.
    /// </returns>
    public RsBuffer? ToCrlNumber()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("ExtensionView");
            }
            Raw.RsBuffer* retVal = Raw.ExtensionView.ToCrlNumber(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new RsBuffer(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.ExtensionView* AsFFI()
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

            Raw.ExtensionView.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~ExtensionView()
    {
        Dispose();
    }
}
