param(
    [switch] $UseMongo,
    [switch] $UseMemory,
    [switch] $UseFile,
    [switch] $SavePickyCertificates,
    [switch] $Verbose,
    [switch] $Debug,
    [switch] $NoClean
)

. "$PSScriptRoot/Private/Base64Url.ps1"
. "$PSScriptRoot/Private/DerToPem.ps1"
. "$PSScriptRoot/Private/GenerateCsrDer.ps1"
. "$PSScriptRoot/Private/PemToDer.ps1"
. "$PSScriptRoot/Private/Hashing.ps1"
. "$PSScriptRoot/Private/ToCert.ps1"

$picky_url = "http://127.0.0.1:12345"
$picky_realm = "WaykDen"
$picky_authority = "${picky_realm} Authority"
$picky_api_key = "secret"

if ($UseMemory) {
    $picky_backend = "memory"
    $picky_database_url = "memory"
} elseif($UseFile) {
    $picky_backend = "file"
    $picky_database_url = "file"
} else {
    $picky_backend = "mongodb"
    $picky_database_url = "mongodb://picky-mongo:27017"
}

if ($Verbose) {
    $VerbosePreference = "Continue"
}

Describe 'picky-server REST API tests' {
    BeforeAll {
        $network = $(docker network ls -qf "name=picky")
        if (!($network)) {
            docker network create picky
        }

        if ($picky_backend -Eq 'mongodb') {
            if ($Verbose) {
                & 'docker' 'stop' 'picky-mongo' 2>&1 | Out-Null
                & 'docker' 'rm' 'picky-mongo' 2>&1 | Out-Null
                & 'docker' 'run' '-d' '-p' '27017:27017' '--network=picky' '--name' 'picky-mongo' 'library/mongo:4.1-bionic'
            } else {
                & 'docker' 'stop' 'picky-mongo' 2>&1 | Out-Null
                & 'docker' 'rm' 'picky-mongo' 2>&1 | Out-Null
                & 'docker' 'run' '-d' '-p' '27017:27017' '--network=picky' '--name' 'picky-mongo' 'library/mongo:4.1-bionic' > $null
            }

            Start-Sleep -s 2 # wait for picky-mongo to be ready
        }

        if ($SavePickyCertificates) {
            $SavePickyCertificatesString = 'true'
        } else {
            $SavePickyCertificatesString = 'false'
        }

        if ($Debug) {
            $location = Get-Location
            $location = "$location/../picky-server/Cargo.toml"
            $location = Resolve-Path $location

            & 'cargo' 'build' '--manifest-path' $location '--quiet'

            Start-Process pwsh `
                -Args "-File ./Private/RunPicky.ps1 $picky_realm $picky_api_key $picky_backend $SavePickyCertificatesString $location -Verbose:$Verbose"
        } else {
            & 'docker' 'stop' 'picky-server'
            & 'docker' 'rm' 'picky-server'
            & 'docker' 'run' '-p' '12345:12345' '-d' '--network=picky' '--name' 'picky-server' `
                '--mount' "source=pickyvolume,target=$currentPath/database/" `
                '-e' "PICKY_REALM=$picky_realm" `
                '-e' "PICKY_API_KEY=$picky_api_key" `
                '-e' "PICKY_BACKEND=$picky_backend" `
                '-e' "PICKY_DATABASE_URL=$picky_database_url" `
                '-e' "PICKY_SAVE_CERTIFICATE=$SavePickyCertificatesString" `
                '-e' "RUST_BACKTRACE=1" `
                'devolutions/picky:3.3.0-buster-dev'
        }
    }

    It 'check health' {
        $s = 0
        while($s -lt 30){
            Start-Sleep -Seconds 2
            try {
                $s = $s + 2
                $result = Invoke-WebRequest -Uri "$picky_url/health" -Method GET
                if($result.StatusCode -eq 200){
                    break;
                }
            } catch {}
        }

        $s | Should -Not -Be 30
    }

    It 'fetch CA chain' {
        $ca_chain = @()

        $contents = Invoke-RestMethod -Uri $picky_url/chain -Method 'GET' -ContentType 'text/plain'
        # https://stackoverflow.com/questions/45884754/powershell-extract-multiple-occurrences-in-multi-lines
        $contents | Select-String  -Pattern '(?smi)^-{2,}BEGIN CERTIFICATE-{2,}.*?-{2,}END CERTIFICATE-{2,}' `
            -Allmatches | ForEach-Object {$_.Matches} | ForEach-Object { $ca_chain += $_.Value }

        Write-Verbose "Fetched chain: $ca_chain"

        $ca_chain.Count | Should -Be 2

        Set-Content -Value $ca_chain[0] -Path "$TestDrive/intermediate_ca.pem"
        $intermediate_ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$TestDrive/intermediate_ca.pem")
        $intermediate_ca.Subject | Should -Be "CN=${picky_realm} Authority"
        $intermediate_ca.Issuer | Should -Be "CN=${picky_realm} Root CA"

        Set-Content -Value $ca_chain[1] -Path "$TestDrive/root_ca.pem"
        $root_ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$TestDrive/root_ca.pem")
        $root_ca.Subject | Should -Be "CN=${picky_realm} Root CA"
        $root_ca.Issuer | Should -Be "CN=${picky_realm} Root CA"
    }

    function CheckSignResponse($response) {
        $response.StatusCode | Should -Be 200

        $signed_cert_pem = [System.Text.Encoding]::ASCII.GetString($response.Content)
        Write-Verbose "Signed Cert: $signed_cert_pem"

        $signed_cert = PemToCert($signed_cert_pem)
        $signed_cert.Subject | Should -Be "CN=test.${picky_realm}"
        $signed_cert.Issuer | Should -Be "CN=${picky_realm} Authority"

        return PemToDer $signed_cert_pem
    }

    It 'sign certificate using JSON with CA and CSR' {
        $csr_der = GenerateCsrDer "CN=test.${picky_realm}"
        $csr_pem = CsrDerToPem $csr_der

        $headers = @{
            "Authorization" = "Bearer $picky_api_key"
            "Accept" = 'application/x-pem-file'
        }

        $payload = [PSCustomObject]@{
            ca="$picky_authority"
            csr="$csr_pem"
        } | ConvertTo-Json

        $response = Invoke-WebRequest `
            -Uri $picky_url/sign/ -Method POST `
            -Headers $headers `
            -ContentType 'application/json' `
            -Body $payload

        CheckSignResponse $response
    }

    It 'sign certificate with CSR wrapped in PEM' {
        $csr_der = GenerateCsrDer "CN=test.${picky_realm}"
        $csr_pem = CsrDerToPem $csr_der

        $headers = @{
            "Authorization" = "Bearer $picky_api_key"
        }

        $response = Invoke-WebRequest `
            -Uri $picky_url/sign/ -Method POST `
            -ContentType 'application/x-pem-file' `
            -Headers $headers `
            -Body $csr_pem

        CheckSignResponse $response
    }

    It 'sign certificate with CSR in base64' {
        $csr_der = GenerateCsrDer "CN=test.${picky_realm}"
        $csr_base64 = [Convert]::ToBase64String($csr_der)

        $headers = @{
            "Authorization" = "Bearer $picky_api_key"
            "Content-Transfer-Encoding" = "base64"
        }

        $response = Invoke-WebRequest `
            -Uri $picky_url/sign/ -Method POST `
            -ContentType 'application/pkcs10' `
            -Headers $headers `
            -Body $csr_base64

        CheckSignResponse $response
    }

    It 'sign certificate request without Content-Transfert-Encoding returns bad request' {
        $csr_der = GenerateCsrDer "CN=test.${picky_realm}"
        $csr_base64 = [Convert]::ToBase64String($csr_der)

        $headers = @{
            "Authorization" = "Bearer $picky_api_key"
        }

        $response = try {
            Invoke-WebRequest `
                -Uri $picky_url/sign/ -Method POST `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $csr_base64
        } catch {
            $_.Exception.Response
        }

        $response.StatusCode | Should -Be 400
    }

    function SignCertAndGetDer {
        $csr_der = GenerateCsrDer "CN=test.${picky_realm}"
        $csr_base64 = [Convert]::ToBase64String($csr_der)

        $headers = @{
            "Authorization" = "Bearer $picky_api_key"
            "Content-Transfer-Encoding" = "base64"
        }
        $response = Invoke-WebRequest `
            -Uri $picky_url/sign/ -Method POST `
            -ContentType 'application/pkcs10' `
            -Headers $headers `
            -Body $csr_base64
        $cert_der = CheckSignResponse $response

        return $cert_der
    }

    It 'fetch cert in binary with upper hex-encoded sha1 address' {
        $cert_der = SignCertAndGetDer
        $hash = HexSha1Hash $cert_der

        $headers = @{
            "Accept-Encoding" = "binary"
            "Accept" = "application/pkix-cert"
        }

        if ($SavePickyCertificates) {
            $response = Invoke-WebRequest `
                -Uri "$picky_url/cert/$hash" `
                -Method GET `
                -Headers $headers
            $response.StatusCode | Should -Be 200
            DerToCert $response.Content
        } else {
            {
                Invoke-RestMethod `
                    -Uri "$picky_url/cert/$hash" `
                    -Method GET `
                    -Headers $headers
            } | Should -Throw
        }
    }

    It 'fetch cert in binary with upper hex-encoded sha256 address' {
        $cert_der = SignCertAndGetDer
        $hash = HexSha256Hash $cert_der

        $headers = @{
            "Accept-Encoding" = "binary"
            "Accept" = "application/pkix-cert"
        }

        if ($SavePickyCertificates) {
            $response = Invoke-WebRequest `
                -Uri "$picky_url/cert/$hash" `
                -Method GET `
                -Headers $headers
            $response.StatusCode | Should -Be 200
            DerToCert $response.Content
        } else {
            {
                Invoke-RestMethod `
                    -Uri "$picky_url/cert/$hash" `
                    -Method GET `
                    -Headers $headers
            } | Should -Throw
        }
    }

    It 'fetch cert in base64 with upper hex-encoded sha256 address' {
        $cert_der = SignCertAndGetDer
        $hash = HexSha256Hash $cert_der

        $headers = @{
            "Accept-Encoding" = "base64"
            "Accept" = "application/pkix-cert"
        }

        if ($SavePickyCertificates) {
            $response = Invoke-WebRequest `
                -Uri "$picky_url/cert/$hash" `
                -Method GET `
                -Headers $headers
            $response.StatusCode | Should -Be 200
            $base64 = [System.Text.Encoding]::ASCII.GetString($response.Content)
            Base64StringToCert $base64
        } else {
            {
                Invoke-RestMethod `
                    -Uri "$picky_url/cert/$hash" `
                    -Method GET `
                    -Headers $headers
            } | Should -Throw
        }
    }

    It 'fetch cert in PEM with upper hex-encoded sha256 address' {
        $cert_der = SignCertAndGetDer
        $hash = HexSha256Hash $cert_der

        $headers = @{
            "Accept" = "application/x-pem-file"
        }

        if ($SavePickyCertificates) {
            $response = Invoke-WebRequest `
                -Uri "$picky_url/cert/$hash" `
                -Method GET `
                -Headers $headers
            $response.StatusCode | Should -Be 200
            $pem = [System.Text.Encoding]::ASCII.GetString($response.Content)
            PemToCert $pem
        } else {
            {
                Invoke-RestMethod `
                    -Uri "$picky_url/cert/$hash" `
                    -Method GET `
                    -Headers $headers
            } | Should -Throw
        }
    }

    It 'register certificate in base64' {
        $csr_der = GenerateCsrDer "CN=test.${picky_realm}"
        $csr_base64 = [Convert]::ToBase64String($csr_der)
        $headers = @{
            "Authorization" = "Bearer $picky_api_key"
            "Content-Transfer-Encoding" = "base64"
            "Accept" = "application/x-pem-file"
        }
        $response = Invoke-WebRequest `
            -Uri $picky_url/sign/ -Method POST `
            -ContentType 'application/pkcs10' `
            -Headers $headers `
            -Body $csr_base64
        $signed_cert_der = CheckSignResponse $response
        $signed_cert_base64 = [Convert]::ToBase64String($signed_cert_der)

        $headers = @{
            "Content-Transfer-Encoding" = "base64"
        }
        $postCert = Invoke-RestMethod -Uri $picky_url/cert/ -Method POST `
            -ContentType 'application/pkix-cert' `
            -Headers $headers `
            -Body $signed_cert_base64
        $postCert | Should -Not -Be $null
    }

    It 'register certificate in json' {
        $csr_der = GenerateCsrDer "CN=test.${picky_realm}"
        $csr_base64 = [Convert]::ToBase64String($csr_der)
        $headers = @{
            "Authorization" = "Bearer $picky_api_key"
            "Content-Transfer-Encoding" = "base64"
            "Accept" = "application/pkix-cert"
            "Accept-Encoding" = "base64"
        }
        $signed_cert_base64 = Invoke-RestMethod -Uri $picky_url/sign/ -Method POST `
            -ContentType 'application/pkcs10' `
            -Headers $headers `
            -Body $csr_base64
        $signed_cert_der = [Convert]::FromBase64String($signed_cert_base64)
        $signed_cert_pem = CertDerToPem $signed_cert_der

        $json = @{
            certificate = $signed_cert_pem
        } | ConvertTo-Json
        $postCert = Invoke-RestMethod -Uri $picky_url/cert/ -Method POST `
            -ContentType 'application/json' `
            -Body $json
        $postCert | Should -Not -Be $null
    }

    It 'register certificate not signed by a picky server CA' {
        $cert_pem = "-----BEGIN CERTIFICATE-----
MIIDPzCCAiegAwIBAgIBATANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER
MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN
MTEwMjEyMTQ0NDA2WhcNMjEwMjEyMTQ0NDA2WjA8MQswCQYDVQQGEwJOTDERMA8G
A1UECgwIUG9sYXJTU0wxGjAYBgNVBAMMEVBvbGFyU1NMIFNlcnZlciAxMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQIfPUBq1VVTi/027oJlLhVhXom/
uOhFkNvuiBZS0/FDUEeWEllkh2v9K+BG+XO+3c+S4ZFb7Wagb4kpeUWA0INq1UFD
d185fAkER4KwVzlw7aPsFRkeqDMIR8EFQqn9TMO0390GH00QUUBncxMPQPhtgSVf
CrFTxjB+FTms+Vruf5KepgVb5xOXhbUjktnUJAbVCSWJdQfdphqPPwkZvq1lLGTr
lZvc/kFeF6babFtpzAK6FCwWJJxK3M3Q91Jnc/EtoCP9fvQxyi1wyokLBNsupk9w
bp7OvViJ4lNZnm5akmXiiD8MlBmj3eXonZUT7Snbq3AS3FrKaxerUoJUsQIDAQAB
o00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBQfdNY/KcF0dEU7BRIsPai9Q1kCpjAf
BgNVHSMEGDAWgBS0WuSls97SUva51aaVD+s+vMf9/zANBgkqhkiG9w0BAQUFAAOC
AQEAm9GKWy4Z6eS483GoR5omwx32meCStm/vFuW+nozRwqwTG5d2Etx4TPnz73s8
fMtM1QB0QbfBDDHxfGymEsKwICmCkJszKE7c03j3mkddrrvN2eIYiL6358S3yHMj
iLVCraRUoEm01k7iytjxrcKb//hxFvHoxD1tdMqbuvjMlTS86kJSrkUMDw68UzfL
jvo3oVjiexfasjsICXFNoncjthKtS7v4zrsgXNPz92h58NgXnDtQU+Eb9tVA9kUs
Ln/az3v5DdgrNoAO60zK1zYAmekLil7pgba/jBLPeAQ2fZVgFxttKv33nUnUBzKA
Od8i323fM5dQS1qQpBjBc/5fPw==
-----END CERTIFICATE-----"

        {
            Invoke-RestMethod -Uri $picky_url/cert/ -Method POST `
                -ContentType 'application/x-pem-file' `
                -Body $cert_pem
        } | Should -Throw
    }

    AfterAll {
        if ($Verbose) {
            if ($UseMongo) {
                & 'docker' 'stop' 'picky-mongo'
                & 'docker' 'rm' 'picky-mongo'
            }

            if ($Debug){
                Stop-Process -Name 'picky-server'
            } else {
                & 'docker' 'stop' 'picky-server'
                & 'docker' 'rm' 'picky-server'
            }
        } else {
            if ($UseMongo) {
                & 'docker' 'stop' 'picky-mongo' > $null
                & 'docker' 'rm' 'picky-mongo' > $null
            }

            if ($Debug) {
                Stop-Process -Name 'picky-server' > $null
            } else {
                & 'docker' 'stop' 'picky-server' > $null
                & 'docker' 'rm' 'picky-server' > $null
            }
        }

        if ($NoClean) {
            return
        }

        if ($UseFile) {
            if ($Verbose) {
                Remove-Item 'database' -Recurse
            } else {
                Remove-Item 'database' -Recurse > $null
            }
        }
    }
}
