// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class RsString: IDisposable
{
    private unsafe Raw.RsString* _inner;

    /// <summary>
    /// Creates a managed <c>RsString</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe RsString(Raw.RsString* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>RsString</c> allocated on Rust side.
    /// </returns>
    public static RsString FromString(string s)
    {
        unsafe
        {
            byte[] sBuf = DiplomatUtils.StringToUtf8(s);
            nuint sBufLength = (nuint)sBuf.Length;
            fixed (byte* sBufPtr = sBuf)
            {
                Raw.RsString* retVal = Raw.RsString.FromString(sBufPtr, sBufLength);
                return new RsString(retVal);
            }
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.RsString* AsFFI()
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

            Raw.RsString.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~RsString()
    {
        Dispose();
    }
}
