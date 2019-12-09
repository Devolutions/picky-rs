. "$PSScriptRoot/DerToPem.ps1"

function PemToCert([String] $pem) {
    Set-Content -Value $pem -Path "$TestDrive/test_cert.crt"
    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$TestDrive/test_cert.crt")
}

function DerToCert([Byte[]] $der) {
    $pem = CertDerToPem $der
    return PemToCert $pem
}

function Base64StringToCert([String] $base64_string) {
    $der = [Convert]::FromBase64String($base64)
    return DerToCert $der
}
