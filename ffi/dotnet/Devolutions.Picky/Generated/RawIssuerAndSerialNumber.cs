using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct IssuerAndSerialNumber
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "IssuerAndSerialNumber_get_issuer", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError GetIssuer(IssuerAndSerialNumber* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "IssuerAndSerialNumber_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(IssuerAndSerialNumber* handle);
}