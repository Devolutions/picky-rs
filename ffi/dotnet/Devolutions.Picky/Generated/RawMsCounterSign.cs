using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct MsCounterSign
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MsCounterSign_get_oid", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetOid(MsCounterSign* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MsCounterSign_get_signed_data", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern SignedData* GetSignedData(MsCounterSign* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MsCounterSign_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(MsCounterSign* handle);
}