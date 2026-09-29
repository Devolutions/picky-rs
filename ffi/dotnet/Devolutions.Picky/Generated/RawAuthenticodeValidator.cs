using System;
using System.Runtime.InteropServices;
using Devolutions.Picky;
using Devolutions.Picky.Diplomat;

namespace Devolutions.Picky.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct AuthenticodeValidator
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_exact_date", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void ExactDate(AuthenticodeValidator* handle, UtcDate* exact);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_interval_date", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void IntervalDate(AuthenticodeValidator* handle, UtcDate* lower, UtcDate* upper);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_require_not_before_check", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void RequireNotBeforeCheck(AuthenticodeValidator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_require_not_after_check", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void RequireNotAfterCheck(AuthenticodeValidator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_ignore_not_before_check", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void IgnoreNotBeforeCheck(AuthenticodeValidator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_ignore_not_after_check", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void IgnoreNotAfterCheck(AuthenticodeValidator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_require_signing_certificate_check", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void RequireSigningCertificateCheck(AuthenticodeValidator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_ignore_signing_certificate_check", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void IgnoreSigningCertificateCheck(AuthenticodeValidator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_require_basic_authenticode_validation", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void RequireBasicAuthenticodeValidation(AuthenticodeValidator* handle, VecU8* expectedFileHash);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_ignore_basic_authenticode_validation", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void IgnoreBasicAuthenticodeValidation(AuthenticodeValidator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_require_chain_check", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void RequireChainCheck(AuthenticodeValidator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_ignore_chain_check", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void IgnoreChainCheck(AuthenticodeValidator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_exclude_cert_authorities", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void ExcludeCertAuthorities(AuthenticodeValidator* handle, DirectoryNameIterator* certAuths);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_verify", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidPickyError Verify(AuthenticodeValidator* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "AuthenticodeValidator_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(AuthenticodeValidator* handle);
}