// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class GeneralName: IDisposable
{
    private unsafe Raw.GeneralName* _inner;

    public GeneralNameType Type
    {
        get
        {
            return GetType();
        }
    }

    /// <summary>
    /// Creates a managed <c>GeneralName</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe GeneralName(Raw.GeneralName* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>GeneralNameType</c> allocated on C# side.
    /// </returns>
    public GeneralNameType GetType()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            Raw.GeneralNameType retVal = Raw.GeneralName.GetType(_inner);
            return (GeneralNameType)retVal;
        }
    }

    /// <returns>
    /// A <c>OtherName</c> allocated on Rust side.
    /// </returns>
    public OtherName? ToOtherName()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            Raw.OtherName* retVal = Raw.GeneralName.ToOtherName(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new OtherName(retVal);
        }
    }

    /// <exception cref="PickyException"></exception>
    public void ToRfc822Name(DiplomatWriteable writable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            Raw.X509NameFfiResultVoidBoxPickyError result = Raw.GeneralName.ToRfc822Name(_inner, &writable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string ToRfc822Name()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            Raw.X509NameFfiResultVoidBoxPickyError result = Raw.GeneralName.ToRfc822Name(_inner, &writeable);
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
    public void ToDnsName(DiplomatWriteable writable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            Raw.X509NameFfiResultVoidBoxPickyError result = Raw.GeneralName.ToDnsName(_inner, &writable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string ToDnsName()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            Raw.X509NameFfiResultVoidBoxPickyError result = Raw.GeneralName.ToDnsName(_inner, &writeable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            string retVal = writeable.ToUnicode();
            writeable.Dispose();
            return retVal;
        }
    }

    /// <returns>
    /// A <c>EdiPartyName</c> allocated on Rust side.
    /// </returns>
    public EdiPartyName? ToEdiPartyName()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            Raw.EdiPartyName* retVal = Raw.GeneralName.ToEdiPartyName(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new EdiPartyName(retVal);
        }
    }

    /// <exception cref="PickyException"></exception>
    public void ToUri(DiplomatWriteable writable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            Raw.X509NameFfiResultVoidBoxPickyError result = Raw.GeneralName.ToUri(_inner, &writable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string ToUri()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            Raw.X509NameFfiResultVoidBoxPickyError result = Raw.GeneralName.ToUri(_inner, &writeable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
            string retVal = writeable.ToUnicode();
            writeable.Dispose();
            return retVal;
        }
    }

    /// <returns>
    /// A <c>Buffer</c> allocated on Rust side.
    /// </returns>
    public Buffer? ToIpAddress()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            Raw.Buffer* retVal = Raw.GeneralName.ToIpAddress(_inner);
            if (retVal == null)
            {
                return null;
            }
            return new Buffer(retVal);
        }
    }

    /// <exception cref="PickyException"></exception>
    public void ToRegisteredId(DiplomatWriteable writable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            Raw.X509NameFfiResultVoidBoxPickyError result = Raw.GeneralName.ToRegisteredId(_inner, &writable);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <exception cref="PickyException"></exception>
    public string ToRegisteredId()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("GeneralName");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            Raw.X509NameFfiResultVoidBoxPickyError result = Raw.GeneralName.ToRegisteredId(_inner, &writeable);
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
    public unsafe Raw.GeneralName* AsFFI()
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

            Raw.GeneralName.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~GeneralName()
    {
        Dispose();
    }
}
