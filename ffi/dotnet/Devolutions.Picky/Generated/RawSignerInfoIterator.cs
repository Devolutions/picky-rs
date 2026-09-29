using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct SignerInfoIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignerInfoIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SignerInfo* Next(SignerInfoIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "SignerInfoIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(SignerInfoIterator* handle);
}