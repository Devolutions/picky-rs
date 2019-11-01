function Get-HashFromByte(
        [Parameter(Mandatory = $true)]
        [byte[]] $DerBytes){

    $sha256Hash = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha256Hash.ComputeHash($DerBytes)

    $hashString = [System.BitConverter]::ToString($hash)
    return $hashString.Replace('-', '').ToLower()
}