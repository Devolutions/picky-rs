function RunPicky(
    [String] $picky_realm,
    [String] $picky_provisioner_public_key,
    [String] $picky_backend,
    [String] $SavePickyCertificatesString,
    [String] $location
) {
    $Env:PICKY_REALM = $picky_realm
    $Env:PICKY_PROVISIONER_PUBLIC_KEY = $picky_provisioner_public_key
    $Env:PICKY_BACKEND = $picky_backend
    $Env:PICKY_SAVE_CERTIFICATE = $SavePickyCertificatesString
    $Env:RUST_BACKTRACE = 1

    & 'cargo' 'run' '--features' 'pre-gen-pk' '--manifest-path' "$location" '--quiet'
}
