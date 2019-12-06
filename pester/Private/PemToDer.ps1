function PemToDer([String] $pem) {
    $base64 = $pem -Replace "`n","" -Replace "`r","" `
                   -Replace "-----BEGIN CERTIFICATE-----", "" `
                   -Replace "-----END CERTIFICATE-----", ""
    return [Convert]::FromBase64String($base64)
}
