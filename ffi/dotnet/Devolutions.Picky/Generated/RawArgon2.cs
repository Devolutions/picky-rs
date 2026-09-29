using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct Argon2
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Argon2_new", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultArgon2PickyError New(Argon2Algorithm algorithm, Argon2Params* parameters);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Argon2_hash_password", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError HashPassword(Argon2* handle, DiplomatSliceU8 password, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "Argon2_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(Argon2* handle);
}