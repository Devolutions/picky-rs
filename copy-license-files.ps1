$WorkspacePath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
Get-ChildItem Cargo.toml -Recurse | ForEach-Object {
    $CratePath = $_.Directory.FullName
    if ($CratePath -ne $WorkspacePath) {
        foreach ($LicenseFile in @('LICENSE-APACHE', 'LICENSE-MIT')) {
            Copy-Item -Path $LicenseFile -Destination (Join-Path $CratePath $LicenseFile) -Force
        }
    }
}