using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct EdiPartyName
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "EdiPartyName_get_name_assigner", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* GetNameAssigner(EdiPartyName* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "EdiPartyName_get_party_name", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DirectoryString* GetPartyName(EdiPartyName* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "EdiPartyName_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(EdiPartyName* handle);
}