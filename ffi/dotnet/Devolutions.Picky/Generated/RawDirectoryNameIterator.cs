using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct DirectoryNameIterator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "DirectoryNameIterator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(DirectoryNameIterator* handle);
}