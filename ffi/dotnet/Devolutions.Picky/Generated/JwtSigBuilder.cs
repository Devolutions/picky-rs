// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky;

#nullable enable

public partial class JwtSigBuilder: IDisposable
{
    private unsafe Raw.JwtSigBuilder* _inner;

    public JwsAlg Algorithm
    {
        set
        {
            SetAlgorithm(value);
        }
    }

    public string Claims
    {
        set
        {
            SetClaims(value);
        }
    }

    public string ContentType
    {
        set
        {
            SetContentType(value);
        }
    }

    public string Kid
    {
        set
        {
            SetKid(value);
        }
    }

    /// <summary>
    /// Creates a managed <c>JwtSigBuilder</c> from a raw handle.
    /// </summary>
    /// <remarks>
    /// Safety: you should not build two managed objects using the same raw handle (may causes use-after-free and double-free).
    /// <br/>
    /// This constructor assumes the raw struct is allocated on Rust side.
    /// If implemented, the custom Drop implementation on Rust side WILL run on destruction.
    /// </remarks>
    public unsafe JwtSigBuilder(Raw.JwtSigBuilder* handle)
    {
        _inner = handle;
    }

    /// <returns>
    /// A <c>JwtSigBuilder</c> allocated on Rust side.
    /// </returns>
    public static JwtSigBuilder Init()
    {
        unsafe
        {
            Raw.JwtSigBuilder* retVal = Raw.JwtSigBuilder.Init();
            return new JwtSigBuilder(retVal);
        }
    }

    public void SetAlgorithm(JwsAlg alg)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            Raw.JwsAlg algRaw;
            algRaw = (Raw.JwsAlg)alg;
            Raw.JwtSigBuilder.SetAlgorithm(_inner, algRaw);
        }
    }

    public void SetContentType(string cty)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            byte[] ctyBuf = DiplomatUtils.StringToUtf8(cty);
            nuint ctyBufLength = (nuint)ctyBuf.Length;
            fixed (byte* ctyBufPtr = ctyBuf)
            {
                Raw.JwtSigBuilder.SetContentType(_inner, ctyBufPtr, ctyBufLength);
            }
        }
    }

    public void SetKid(string kid)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            byte[] kidBuf = DiplomatUtils.StringToUtf8(kid);
            nuint kidBufLength = (nuint)kidBuf.Length;
            fixed (byte* kidBufPtr = kidBuf)
            {
                Raw.JwtSigBuilder.SetKid(_inner, kidBufPtr, kidBufLength);
            }
        }
    }

    /// <summary>
    /// Adds a JSON object as additional header parameter.
    /// </summary>
    /// <remarks>
    /// This additional header parameter may be either public or private.
    /// </remarks>
    /// <exception cref="PickyException"></exception>
    public void AddAdditionalParameterObject(string name, string obj)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            byte[] nameBuf = DiplomatUtils.StringToUtf8(name);
            byte[] objBuf = DiplomatUtils.StringToUtf8(obj);
            nuint nameBufLength = (nuint)nameBuf.Length;
            nuint objBufLength = (nuint)objBuf.Length;
            fixed (byte* nameBufPtr = nameBuf)
            {
                fixed (byte* objBufPtr = objBuf)
                {
                    Raw.JwtFfiResultVoidBoxPickyError result = Raw.JwtSigBuilder.AddAdditionalParameterObject(_inner, nameBufPtr, nameBufLength, objBufPtr, objBufLength);
                    if (!result.isOk)
                    {
                        throw new PickyException(new PickyError(result.Err));
                    }
                }
            }
        }
    }

    /// <summary>
    /// Adds a boolean as additional header parameter.
    /// </summary>
    /// <remarks>
    /// This additional header parameter may be either public or private.
    /// </remarks>
    public void AddAdditionalParameterBool(string name, bool value)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            byte[] nameBuf = DiplomatUtils.StringToUtf8(name);
            nuint nameBufLength = (nuint)nameBuf.Length;
            fixed (byte* nameBufPtr = nameBuf)
            {
                Raw.JwtSigBuilder.AddAdditionalParameterBool(_inner, nameBufPtr, nameBufLength, value);
            }
        }
    }

    /// <summary>
    /// Adds a positive number as additional header parameter.
    /// </summary>
    /// <remarks>
    /// This additional header parameter may be either public or private.
    /// </remarks>
    public void AddAdditionalParameterPosInt(string name, ulong value)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            byte[] nameBuf = DiplomatUtils.StringToUtf8(name);
            nuint nameBufLength = (nuint)nameBuf.Length;
            fixed (byte* nameBufPtr = nameBuf)
            {
                Raw.JwtSigBuilder.AddAdditionalParameterPosInt(_inner, nameBufPtr, nameBufLength, value);
            }
        }
    }

    /// <summary>
    /// Adds a possibly negative number as additional header parameter.
    /// </summary>
    /// <remarks>
    /// This additional header parameter may be either public or private.
    /// </remarks>
    public void AddAdditionalParameterNegInt(string name, long value)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            byte[] nameBuf = DiplomatUtils.StringToUtf8(name);
            nuint nameBufLength = (nuint)nameBuf.Length;
            fixed (byte* nameBufPtr = nameBuf)
            {
                Raw.JwtSigBuilder.AddAdditionalParameterNegInt(_inner, nameBufPtr, nameBufLength, value);
            }
        }
    }

    /// <summary>
    /// Adds a float as additional header parameter.
    /// </summary>
    /// <remarks>
    /// This additional header parameter may be either public or private.
    /// </remarks>
    public void AddAdditionalParameterFloat(string name, long value)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            byte[] nameBuf = DiplomatUtils.StringToUtf8(name);
            nuint nameBufLength = (nuint)nameBuf.Length;
            fixed (byte* nameBufPtr = nameBuf)
            {
                Raw.JwtSigBuilder.AddAdditionalParameterFloat(_inner, nameBufPtr, nameBufLength, value);
            }
        }
    }

    /// <summary>
    /// Adds a float as additional header parameter.
    /// </summary>
    /// <remarks>
    /// This additional header parameter may be either public or private.
    /// </remarks>
    public void AddAdditionalParameterString(string name, string value)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            byte[] nameBuf = DiplomatUtils.StringToUtf8(name);
            byte[] valueBuf = DiplomatUtils.StringToUtf8(value);
            nuint nameBufLength = (nuint)nameBuf.Length;
            nuint valueBufLength = (nuint)valueBuf.Length;
            fixed (byte* nameBufPtr = nameBuf)
            {
                fixed (byte* valueBufPtr = valueBuf)
                {
                    Raw.JwtSigBuilder.AddAdditionalParameterString(_inner, nameBufPtr, nameBufLength, valueBufPtr, valueBufLength);
                }
            }
        }
    }

    /// <summary>
    /// Sets the given JSON payload.
    /// </summary>
    /// <remarks>
    /// Claims should be a valid JSON payload.
    /// </remarks>
    /// <exception cref="PickyException"></exception>
    public void SetClaims(string claims)
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            byte[] claimsBuf = DiplomatUtils.StringToUtf8(claims);
            nuint claimsBufLength = (nuint)claimsBuf.Length;
            fixed (byte* claimsBufPtr = claimsBuf)
            {
                Raw.JwtFfiResultVoidBoxPickyError result = Raw.JwtSigBuilder.SetClaims(_inner, claimsBufPtr, claimsBufLength);
                if (!result.isOk)
                {
                    throw new PickyException(new PickyError(result.Err));
                }
            }
        }
    }

    /// <returns>
    /// A <c>JwtSig</c> allocated on Rust side.
    /// </returns>
    public JwtSig Build()
    {
        unsafe
        {
            if (_inner == null)
            {
                throw new ObjectDisposedException("JwtSigBuilder");
            }
            Raw.JwtSig* retVal = Raw.JwtSigBuilder.Build(_inner);
            return new JwtSig(retVal);
        }
    }

    /// <summary>
    /// Returns the underlying raw handle.
    /// </summary>
    public unsafe Raw.JwtSigBuilder* AsFFI()
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

            Raw.JwtSigBuilder.Destroy(_inner);
            _inner = null;

            GC.SuppressFinalize(this);
        }
    }

    ~JwtSigBuilder()
    {
        Dispose();
    }
}
