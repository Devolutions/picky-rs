// <auto-generated/> by Diplomat

#pragma warning disable 0105
using System;
using System.Runtime.InteropServices;

using Devolutions.Picky.Diplomat;
#pragma warning restore 0105

namespace Devolutions.Picky.Raw;

#nullable enable

[StructLayout(LayoutKind.Sequential)]
public partial struct Argon2FfiResultBoxArgon2BoxPickyError
{
#if __IOS__
    private const string NativeLib = "libDevolutionsPicky.framework/libDevolutionsPicky";
#else
    private const string NativeLib = "DevolutionsPicky";
#endif

    [StructLayout(LayoutKind.Explicit)]
    private unsafe struct InnerUnion
    {
        [FieldOffset(0)]
        internal Argon2* ok;
        [FieldOffset(0)]
        internal PickyError* err;
    }

    private InnerUnion _inner;

    [MarshalAs(UnmanagedType.U1)]
    public bool isOk;

    public unsafe Argon2* Ok
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

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "result_box_Argon2_box_PickyError_destroy", ExactSpelling = true)]
    public static unsafe extern void Destroy(IntPtr self);
}
