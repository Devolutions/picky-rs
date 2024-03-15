// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class Time: IDisposable
{
    private unsafe Raw.Time* _inner;

    public byte Day
    {
        get
        {
            return GetDay();
        }
    }

    public byte Hour
    {
        get
        {
            return GetHour();
        }
    }

    public byte Minute
    {
        get
        {
            return GetMinute();
        }
    }

    public byte Month
    {
        get
        {
            return GetMonth();
        }
    }

    public byte Second
    {
        get
        {
            return GetSecond();
        }
    }

    public ushort Year
    {
        get
        {
            return GetYear();
        }
    }

    /// <summary>
    /// Creates a managed <c>Time</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe Time(Raw.Time* handle)
    {
        _inner = handle;
    }

    public ushort GetYear()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Time");
            }
            ushort retVal = Raw.Time.GetYear(_inner);
            return retVal;
        }
    }

    public byte GetMonth()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Time");
            }
            byte retVal = Raw.Time.GetMonth(_inner);
            return retVal;
        }
    }

    public byte GetDay()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Time");
            }
            byte retVal = Raw.Time.GetDay(_inner);
            return retVal;
        }
    }

    public byte GetHour()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Time");
            }
            byte retVal = Raw.Time.GetHour(_inner);
            return retVal;
        }
    }

    public byte GetMinute()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Time");
            }
            byte retVal = Raw.Time.GetMinute(_inner);
            return retVal;
        }
    }

    public byte GetSecond()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Time");
            }
            byte retVal = Raw.Time.GetSecond(_inner);
            return retVal;
        }
    }

    public bool IsUtc()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Time");
            }
            bool retVal = Raw.Time.IsUtc(_inner);
            return retVal;
        }
    }

    public bool IsGeneralized()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Time");
            }
            bool retVal = Raw.Time.IsGeneralized(_inner);
            return retVal;
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.Time* AsFFI()
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

            Raw.Time.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~Time()
    {
        Dispose();
    }
}
