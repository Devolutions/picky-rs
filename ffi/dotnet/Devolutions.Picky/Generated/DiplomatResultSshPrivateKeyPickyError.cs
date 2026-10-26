using System;
using System.Runtime.InteropServices;

namespace Devolutions.Picky.Raw;

using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

[StructLayout(LayoutKind.Sequential)]
internal partial struct DiplomatResultSshPrivateKeyPickyError
{
    [StructLayout(LayoutKind.Explicit)]
    private unsafe struct InnerUnion
    {
        [FieldOffset(0)] internal SshPrivateKey* ok;
        [FieldOffset(0)] internal PickyError* err;
    }

    private InnerUnion _inner;

    public DiplomatBool IsOk;
    public unsafe SshPrivateKey* Ok => IsOk ? _inner.ok : throw new InvalidOperationException("Result does not contain Ok value");
    public unsafe PickyError* Err => !IsOk ? _inner.err : throw new InvalidOperationException("Result does not contain Err value");
}