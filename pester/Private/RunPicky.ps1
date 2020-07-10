param(
    [string] $picky_realm,
    [string] $picky_backend,
    [string] $SavePickyCertificatesString,
    [string] $location,
    [switch] $Verbose
)

$picky_provisioner_public_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6CbtUnGihZ7UIYfc/m94
GjsSZptk7zIdiraDMPns3ziKjxsgJhwCLjal1MgTgKSI6U2hnV8wV+L7iSC+0AcE
O2PDlsVv1KeTySLatDBmlXcH0mK6PeBR0NAlJfgRo6PL+isZuBTn8c/bbG1hI8Rs
8lHChH2wT48mQrkBhS5okdJA79fOFFWlKbbFnhDxd8PmazKHXqYArMo3hzxmN3OS
x56x+lRUBvGunSIDKyb100HnG9Lm4P9v6pxVXHlZy+umzlA++ETDj899gRxCMd/6
5i5kfMZcAAOQrVkt/vtLNJmEfKr9MEvmHYBCrvwy0mc8be5YiSL+ZjFMhRpcb7Bw
cwIDAQAB
-----END PUBLIC KEY-----"

$Env:PICKY_REALM = $picky_realm
$Env:PICKY_PROVISIONER_PUBLIC_KEY = $picky_provisioner_public_key
$Env:PICKY_BACKEND = $picky_backend
$Env:PICKY_SAVE_CERTIFICATE = $SavePickyCertificatesString
$Env:RUST_BACKTRACE = 1

if ($Verbose) {
    & 'cargo' 'run' '--features' 'pre-gen-pk' '--manifest-path' "$location" '--quiet'
} else {
    & 'cargo' 'run' '--features' 'pre-gen-pk' '--manifest-path' "$location" '--quiet' > $null
}
