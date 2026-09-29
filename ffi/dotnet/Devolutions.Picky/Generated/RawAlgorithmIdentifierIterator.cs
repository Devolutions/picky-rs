using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AlgorithmIdentifierIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifierIterator_next", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern AlgorithmIdentifier* Next(AlgorithmIdentifierIterator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AlgorithmIdentifierIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AlgorithmIdentifierIterator* handle);
}