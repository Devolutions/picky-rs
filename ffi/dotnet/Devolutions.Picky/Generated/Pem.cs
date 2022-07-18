// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

/// <summary>
/// PEM object.
/// </summary>
public partial class Pem: IDisposable
{
    private unsafe Raw.Pem* _inner;

    public ulong DataLength
    {
        get
        {
            return GetDataLength();
        }
    }

    public string Label
    {
        get
        {
            return GetLabel();
        }
    }

    /// <summary>
    /// Creates a managed <c>Pem</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe Pem(Raw.Pem* handle)
    {
        _inner = handle;
    }

    /// <summary>
    /// Creates a PEM object with the given label and data.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>Pem</c> allocated on Rust side.
    /// </returns>
    public static Pem New(string label, byte[] data)
    {
        unsafe
        {
            byte[] labelBuf = DiplomatUtils.StringToUtf8(label);
            nuint dataLength = (nuint)data.Length;
            nuint labelBufLength = (nuint)labelBuf.Length;
            fixed (byte* dataPtr = data)
            {
                fixed (byte* labelBufPtr = labelBuf)
                {
                    IntPtr resultPtr = Raw.Pem.New(labelBufPtr, labelBufLength, dataPtr, dataLength);
                    Raw.PemFfiResultBoxPemBoxPickyError result = Marshal.PtrToStructure<Raw.PemFfiResultBoxPemBoxPickyError>(resultPtr);
                    Raw.PemFfiResultBoxPemBoxPickyError.Destroy(resultPtr);
                    if (!result.isOk)
                    {
                        throw new PickyException(new PickyError(result.Err));
                    }
                    Raw.Pem* retVal = result.Ok;
                    return new Pem(retVal);
                }
            }
        }
    }

    /// <summary>
    /// Loads a PEM from the filesystem.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>Pem</c> allocated on Rust side.
    /// </returns>
    public static Pem LoadFromFile(string path)
    {
        unsafe
        {
            byte[] pathBuf = DiplomatUtils.StringToUtf8(path);
            nuint pathBufLength = (nuint)pathBuf.Length;
            fixed (byte* pathBufPtr = pathBuf)
            {
                IntPtr resultPtr = Raw.Pem.LoadFromFile(pathBufPtr, pathBufLength);
                Raw.PemFfiResultBoxPemBoxPickyError result = Marshal.PtrToStructure<Raw.PemFfiResultBoxPemBoxPickyError>(resultPtr);
                Raw.PemFfiResultBoxPemBoxPickyError.Destroy(resultPtr);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
                Raw.Pem* retVal = result.Ok;
                return new Pem(retVal);
            }
        }
    }

    /// <summary>
    /// Saves this PEM object to the filesystem.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public void SaveToFile(string path)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Pem");
            }
            byte[] pathBuf = DiplomatUtils.StringToUtf8(path);
            nuint pathBufLength = (nuint)pathBuf.Length;
            fixed (byte* pathBufPtr = pathBuf)
            {
                IntPtr resultPtr = Raw.Pem.SaveToFile(_inner, pathBufPtr, pathBufLength);
                Raw.PemFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.PemFfiResultVoidBoxPickyError>(resultPtr);
                Raw.PemFfiResultVoidBoxPickyError.Destroy(resultPtr);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
            }
        }
    }

    /// <summary>
    /// Parses a PEM-encoded string representation.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    /// <returns>
    /// A <c>Pem</c> allocated on Rust side.
    /// </returns>
    public static Pem Parse(string input)
    {
        unsafe
        {
            byte[] inputBuf = DiplomatUtils.StringToUtf8(input);
            nuint inputBufLength = (nuint)inputBuf.Length;
            fixed (byte* inputBufPtr = inputBuf)
            {
                IntPtr resultPtr = Raw.Pem.Parse(inputBufPtr, inputBufLength);
                Raw.PemFfiResultBoxPemBoxPickyError result = Marshal.PtrToStructure<Raw.PemFfiResultBoxPemBoxPickyError>(resultPtr);
                Raw.PemFfiResultBoxPemBoxPickyError.Destroy(resultPtr);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
                Raw.Pem* retVal = result.Ok;
                return new Pem(retVal);
            }
        }
    }

    /// <summary>
    /// Returns the length of the data contained by this PEM object.
    /// </summary>
    public ulong GetDataLength()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Pem");
            }
            ulong retVal = Raw.Pem.GetDataLength(_inner);
            return retVal;
        }
    }

    /// <summary>
    /// Returns the label of this PEM object.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public void GetLabel(DiplomatWriteable writeable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Pem");
            }
            IntPtr resultPtr = Raw.Pem.GetLabel(_inner, &writeable);
            Raw.PemFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.PemFfiResultVoidBoxPickyError>(resultPtr);
            Raw.PemFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <summary>
    /// Returns the label of this PEM object.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public string GetLabel()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Pem");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            IntPtr resultPtr = Raw.Pem.GetLabel(_inner, &writeable);
            Raw.PemFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.PemFfiResultVoidBoxPickyError>(resultPtr);
            Raw.PemFfiResultVoidBoxPickyError.Destroy(resultPtr);
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
    /// Returns the string representation of this PEM object.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public void ToRepr(DiplomatWriteable writeable)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Pem");
            }
            IntPtr resultPtr = Raw.Pem.ToRepr(_inner, &writeable);
            Raw.PemFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.PemFfiResultVoidBoxPickyError>(resultPtr);
            Raw.PemFfiResultVoidBoxPickyError.Destroy(resultPtr);
            if (!result.isOk)
            {
                throw new PickyException(new PickyError(result.Err));
            }
        }
    }

    /// <summary>
    /// Returns the string representation of this PEM object.
    /// </summary>
    /// <exception cref="PickyException"></exception>
    public string ToRepr()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("Pem");
            }
            DiplomatWriteable writeable = new DiplomatWriteable();
            IntPtr resultPtr = Raw.Pem.ToRepr(_inner, &writeable);
            Raw.PemFfiResultVoidBoxPickyError result = Marshal.PtrToStructure<Raw.PemFfiResultVoidBoxPickyError>(resultPtr);
            Raw.PemFfiResultVoidBoxPickyError.Destroy(resultPtr);
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
    public unsafe Raw.Pem* AsFFI()
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

            Raw.Pem.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~Pem()
    {
        Dispose();
    }
}
