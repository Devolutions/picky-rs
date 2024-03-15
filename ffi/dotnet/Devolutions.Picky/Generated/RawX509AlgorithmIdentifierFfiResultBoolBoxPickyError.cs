// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct X509AlgorithmIdentifierFfiResultBoolBoxPickyError
{
    [StructLayout(LayoutKind.Explicit)]
    private unsafe struct InnerUnion
    {
        [FieldOffset(0)]
        internal bool ok;
        [FieldOffset(0)]
        internal PickyError* err;
    }

    private InnerUnion _inner;

    [MarshalAs(UnmanagedType.U1)]
    public bool isOk;

    public unsafe bool Ok
    {
        get
        {
            return _inner.ok;
        }
    }

    public unsafe PickyError* Err
    {
        get
        {
            return _inner.err;
        }
    }
}
