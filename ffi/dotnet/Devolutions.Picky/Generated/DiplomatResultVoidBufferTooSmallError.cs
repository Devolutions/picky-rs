using System;
using System.Runtime.InteropServices;

namespace Devolutions.Picky.Raw;

using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

[StructLayout(LayoutKind.Sequential)]
internal partial struct DiplomatResultVoidBufferTooSmallError
{
    [StructLayout(LayoutKind.Explicit)]
    private unsafe struct InnerUnion
    {
        [FieldOffset(0)] internal BufferTooSmallError* err;
    }

    private InnerUnion _inner;

    public DiplomatBool IsOk;
    public unsafe BufferTooSmallError* Err => !IsOk ? _inner.err : throw new InvalidOperationException("Result does not contain Err value");
}