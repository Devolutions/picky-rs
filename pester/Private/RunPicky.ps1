param(
    [string] $picky_realm,
    [string] $picky_api_key,
    [string] $picky_backend,
    [string] $SavePickyCertificatesString,
    [string] $location,
    [switch] $Verbose
)

$Env:PICKY_REALM = $picky_realm
$Env:PICKY_API_KEY = $picky_api_key
$Env:PICKY_BACKEND = $picky_backend
$Env:PICKY_SAVE_CERTIFICATE = $SavePickyCertificatesString
$Env:RUST_BACKTRACE = 1

if ($Verbose) {
    & 'cargo' 'run' '--features' 'pre-gen-pk' '--manifest-path' "$location"
} else {
    & 'cargo' 'run' '--features' 'pre-gen-pk' '--manifest-path' "$location" > $null
}
