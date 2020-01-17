function HexSha256Hash([Parameter(Mandatory = $true)] [byte[]] $DerBytes) {
    $sha256Hash = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha256Hash.ComputeHash($DerBytes)
    return 'F1220' + [System.BitConverter]::ToString($hash).Replace('-', '')
}

function HexSha1Hash([Parameter(Mandatory = $true)] [byte[]] $DerBytes) {
    $sha256Hash = [System.Security.Cryptography.SHA1]::Create()
    $hash = $sha256Hash.ComputeHash($DerBytes)
    return 'F1114' + [System.BitConverter]::ToString($hash).Replace('-', '')
}
