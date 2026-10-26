using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct JwtSigBuilder
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_init", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern JwtSigBuilder* Init();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_set_algorithm", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetAlgorithm(JwtSigBuilder* handle, JwsAlg alg);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_set_content_type", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetContentType(JwtSigBuilder* handle, DiplomatSliceU8 cty);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_set_kid", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void SetKid(JwtSigBuilder* handle, DiplomatSliceU8 kid);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_add_additional_parameter_object", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError AddAdditionalParameterObject(JwtSigBuilder* handle, DiplomatSliceU8 name, DiplomatSliceU8 obj);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_add_additional_parameter_bool", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void AddAdditionalParameterBool(JwtSigBuilder* handle, DiplomatSliceU8 name, [MarshalAs(UnmanagedType.U1)] bool value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_add_additional_parameter_pos_int", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void AddAdditionalParameterPosInt(JwtSigBuilder* handle, DiplomatSliceU8 name, ulong value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_add_additional_parameter_neg_int", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void AddAdditionalParameterNegInt(JwtSigBuilder* handle, DiplomatSliceU8 name, long value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_add_additional_parameter_float", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void AddAdditionalParameterFloat(JwtSigBuilder* handle, DiplomatSliceU8 name, long value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_add_additional_parameter_string", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void AddAdditionalParameterString(JwtSigBuilder* handle, DiplomatSliceU8 name, DiplomatSliceU8 value);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_set_claims", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError SetClaims(JwtSigBuilder* handle, DiplomatSliceU8 claims);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_build", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern JwtSig* Build(JwtSigBuilder* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "JwtSigBuilder_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(JwtSigBuilder* handle);
}