using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct RevocationInfoChoiceIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RevocationInfoChoiceIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern RevocationInfoChoice* Next(RevocationInfoChoiceIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "RevocationInfoChoiceIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(RevocationInfoChoiceIterator* handle);
}