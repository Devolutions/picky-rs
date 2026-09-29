using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AesAuthEncParams
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AesAuthEncParams_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AesAuthEncParams* handle);
}