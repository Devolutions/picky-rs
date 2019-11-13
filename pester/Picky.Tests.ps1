param(
	[switch] $UseMongo,
	[switch] $UseMemory,
	[switch] $UseFile,
	[switch] $SavePickyCertificates,
	[switch] $Silent,
	[switch] $Debug
)

. "$PSScriptRoot/Private/Base64Url.ps1"
. "$PSScriptRoot/Private/SHA256.ps1"

$picky_url = "http://127.0.0.1:12345"
$picky_realm = "WaykDen"
$picky_authority = "${picky_realm} Authority"
$picky_api_key = "secret"

Describe 'Picky tests' {
	BeforeAll {
		$picky_realm = "WaykDen"
		$picky_api_key = "secret"

		if ($UseMemory){
			$picky_backend = "memory"
			$picky_database_url = "memory"
		}
		elseif($UseFile){
			$picky_backend = "file"
			$picky_database_url = "file"
		}
		else{
			$picky_backend = "mongodb"
			$picky_database_url = "mongodb://picky-mongo:27017"
		}

		$network = $(docker network ls -qf "name=picky")
		if(!($network)){
			docker network create picky
		}

		if ($picky_backend -Eq 'mongodb') {
			if($Silent){
				[void](& 'docker' 'stop' 'picky-mongo')
				[void](& 'docker' 'rm' 'picky-mongo')
				[void](& 'docker' 'run' '-d' '-p' '27017:27017' '--network=picky' '--name' 'picky-mongo' `
		    'library/mongo:4.1-bionic')
			}else{
				& 'docker' 'stop' 'picky-mongo'
				& 'docker' 'rm' 'picky-mongo'
				& 'docker' 'run' '-d' '-p' '27017:27017' '--network=picky' '--name' 'picky-mongo' `
		    'library/mongo:4.1-bionic'
			}

			Start-Sleep -s 2 # wait for picky-mongo to be ready
		}

		$SavePickyCertificatesString = 'false'
		if($SavePickyCertificates){
			$SavePickyCertificatesString = 'true'
		}

		$currentPath = Get-Location
		if(!(Test-Path "$currentPath/database/")){
			& 'mkdir' './database/'
		}

		if($Debug){
			$location = Get-Location
			$location = "$location/../picky-server/Cargo.toml"
			$location = Resolve-Path $location

			Write-Host "Build Picky Server ..."
			& 'cargo' 'build' '--manifest-path' '../picky-server/Cargo.toml'
			if($Silent){
				Start-Process pwsh -Args "-File ./Private/RunPicky.ps1 $picky_realm $picky_api_key $picky_backend $SavePickyCertificatesString $location -Silent"
			}else{
				Start-Process pwsh -Args "-File ./Private/RunPicky.ps1 $picky_realm $picky_api_key $picky_backend $SavePickyCertificatesString $location"
			}
		}
		else{
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

	It 'checks health' {
		$s = 0
		$code = 400
		while($s -lt 30){
			Start-Sleep -Seconds 2
			try{
				$s = $s + 2
				$result = Invoke-WebRequest -Uri "$picky_url/health" -Method GET
				$code = $result.StatusCode
				if($code -eq 200){
					break;
				}
			}
			catch{
				#miam
			}
		}
		
		$s | Should -Not -Be 30
	}

	It 'gets CA chain' {
		$authority_base64 = ConvertTo-Base64Url $picky_authority
		$contents = Invoke-RestMethod -Uri $picky_url/chain/$authority_base64 -Method 'GET' `
			-ContentType 'text/plain'

		$ca_chain = @()
		# https://stackoverflow.com/questions/45884754/powershell-extract-multiple-occurrences-in-multi-lines
		$contents | Select-String  -Pattern '(?smi)^-{2,}BEGIN CERTIFICATE-{2,}.*?-{2,}END CERTIFICATE-{2,}' `
			-Allmatches | ForEach-Object {$_.Matches} | ForEach-Object { $ca_chain += $_.Value }

		$ca_chain.Count | Should -Be 2
		Set-Content -Value $ca_chain[0] -Path "$TestDrive/intermediate_ca.pem"
		Set-Content -Value $ca_chain[1] -Path "$TestDrive/root_ca.pem"

		$root_ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$TestDrive/root_ca.pem")
		$intermediate_ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$TestDrive/intermediate_ca.pem")

		$intermediate_ca.Subject | Should -Be "CN=${picky_realm} Authority"
		$intermediate_ca.Issuer | Should -Be "CN=${picky_realm} Root CA"

		$root_ca.Subject | Should -Be "CN=${picky_realm} Root CA"
		$root_ca.Issuer | Should -Be "CN=${picky_realm} Root CA"
	}

	It 'signs certificates JSON with CA and CSR' {
		# https://stackoverflow.com/questions/48196350/generate-and-sign-certificate-request-using-pure-net-framework
		# https://www.powershellgallery.com/packages/SelfSignedCertificate/0.0.4/Content/SelfSignedCertificate.psm1

		$key_size = 2048
		$subject = "CN=test.${picky_realm}"
		$rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)

		$certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				$subject, $rsa_key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

		$csr_der = $certRequest.CreateSigningRequest()

		$sb = [System.Text.StringBuilder]::new()
		$csr_base64 = [Convert]::ToBase64String($csr_der)

		$offset = 0
		$line_length = 64
		$sb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----")
		while ($offset -lt $csr_base64.Length) {
			$line_end = [Math]::Min($offset + $line_length, $csr_base64.Length)
			$sb.AppendLine($csr_base64.Substring($offset, $line_end - $offset))
			$offset = $line_end
		}
		$sb.AppendLine("-----END CERTIFICATE REQUEST-----")
		$csr_pem = $sb.ToString()

		if(!($Silent)){
			Write-Host $csr_pem
		}

		Set-Content -Value $csr_pem -Path "$TestDrive/test.csr"
		$csr = Get-Content "$TestDrive/test.csr" | Out-String

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
		}

		$payload = [PSCustomObject]@{
			ca="$picky_authority"
			csr="$csr"
		} | ConvertTo-Json

		$cert = Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
			-Headers $headers `
			-ContentType 'application/json' `
			-Body $payload

		Set-Content -Value $cert -Path "$TestDrive/test.crt"
		$leaf_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$TestDrive/test.crt")
		if(!($Silent))		{
			Write-Host $leaf_cert
		}
		$leaf_cert.Subject | Should -Be "CN=test.${picky_realm}"
		$leaf_cert.Issuer | Should -Be "CN=${picky_realm} Authority"
	}

	It 'signs certificates with CSR as base64' {
		# https://stackoverflow.com/questions/48196350/generate-and-sign-certificate-request-using-pure-net-framework
		# https://www.powershellgallery.com/packages/SelfSignedCertificate/0.0.4/Content/SelfSignedCertificate.psm1

		$key_size = 2048
		$subject = "CN=test.${picky_realm}"
		$rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)

		$certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				$subject, $rsa_key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

		$csr_der = $certRequest.CreateSigningRequest()

		$sb = [System.Text.StringBuilder]::new()
		$csr_base64 = [Convert]::ToBase64String($csr_der)

		$offset = 0
		$line_length = 64
		$sb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----")
		while ($offset -lt $csr_base64.Length) {
			$line_end = [Math]::Min($offset + $line_length, $csr_base64.Length)
			$sb.AppendLine($csr_base64.Substring($offset, $line_end - $offset))
			$offset = $line_end
		}
		$sb.AppendLine("-----END CERTIFICATE REQUEST-----")
		$csr_pem = $sb.ToString()

		if(!($Silent)){
			Write-Host $csr_pem
		}

		Set-Content -Value $csr_pem -Path "$TestDrive/test.csr"
		$csr = Get-Content "$TestDrive/test.csr" | Out-String

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
			"Content-Transfer-Encoding" = "base64"
			"Content-Disposition" = "attachment"
		}

		$cert = Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $csr

		Set-Content -Value $cert -Path "$TestDrive/test.crt"
		$leaf_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$TestDrive/test.crt")

		if(!($Silent)){
			Write-Host $leaf_cert
		}

		$leaf_cert.Subject | Should -Be "CN=test.${picky_realm}"
		$leaf_cert.Issuer | Should -Be "CN=${picky_realm} Authority"
	}

	It 'signs certificates With CSR as binary' {
		# https://stackoverflow.com/questions/48196350/generate-and-sign-certificate-request-using-pure-net-framework
		# https://www.powershellgallery.com/packages/SelfSignedCertificate/0.0.4/Content/SelfSignedCertificate.psm1

		$key_size = 2048
		$subject = "CN=test.${picky_realm}"
		$rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)

		$certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				$subject, $rsa_key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

		$csr_der = $certRequest.CreateSigningRequest()

		$sb = [System.Text.StringBuilder]::new()
		$csr_base64 = [Convert]::ToBase64String($csr_der)

		$offset = 0
		$line_length = 64
		$sb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----")
		while ($offset -lt $csr_base64.Length) {
			$line_end = [Math]::Min($offset + $line_length, $csr_base64.Length)
			$sb.AppendLine($csr_base64.Substring($offset, $line_end - $offset))
			$offset = $line_end
		}
		$sb.AppendLine("-----END CERTIFICATE REQUEST-----")
		$csr_pem = $sb.ToString()

		if(!($Silent)){
			Write-Host $csr_pem
		}

		Set-Content -Value $csr_pem -Path "$TestDrive/test.csr"
		$csr = Get-Content "$TestDrive/test.csr" | Out-String

		$csr = [Convert]::FromBase64String($csr_base64)

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
			"Content-Transfer-Encoding" = "binary"
			"Content-Disposition" = "attachment"
		}

		$cert = Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $csr

		Set-Content -Value $cert -Path "$TestDrive/test.crt"
		$leaf_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$TestDrive/test.crt")
		if(!($Silent)){
			Write-Host $leaf_cert
		}

		$leaf_cert.Subject | Should -Be "CN=test.${picky_realm}"
		$leaf_cert.Issuer | Should -Be "CN=${picky_realm} Authority"
	}


	It 'signs certificates which failed, Send without Content-Transfert-Encoding' {
		# https://stackoverflow.com/questions/48196350/generate-and-sign-certificate-request-using-pure-net-framework
		# https://www.powershellgallery.com/packages/SelfSignedCertificate/0.0.4/Content/SelfSignedCertificate.psm1

		$key_size = 2048
		$subject = "CN=test.${picky_realm}"
		$rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)

		$certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				$subject, $rsa_key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

		$csr_der = $certRequest.CreateSigningRequest()

		$sb = [System.Text.StringBuilder]::new()
		$csr_base64 = [Convert]::ToBase64String($csr_der)

		$offset = 0
		$line_length = 64
		$sb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----")
		while ($offset -lt $csr_base64.Length) {
			$line_end = [Math]::Min($offset + $line_length, $csr_base64.Length)
			$sb.AppendLine($csr_base64.Substring($offset, $line_end - $offset))
			$offset = $line_end
		}
		$sb.AppendLine("-----END CERTIFICATE REQUEST-----")
		$csr_pem = $sb.ToString()

		Set-Content -Value $csr_pem -Path "$TestDrive/test.csr"
		$csr = Get-Content "$TestDrive/test.csr" | Out-String

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
			"Content-Disposition" = "attachment"
		}

		try{
			Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
			-ContentType 'application/pkcs10' `
			-Headers $headers `
			-Body $csr
		}
		catch{
			if(!($Silent)){
				Write-Host $_
			}
			return;
		}

		throw "This test sould catch the web-request"
	}

	It 'Get cert in binary with sha256' {
		$key_size = 2048
		$subject = "CN=test.${picky_realm}"
		$rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)

		$certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				$subject, $rsa_key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

		$csr_der = $certRequest.CreateSigningRequest()

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
			"Content-Transfer-Encoding" = "binary"
			"Content-Disposition" = "attachment"
		}

		$cert = Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $csr_der

		$cert = $cert -Replace "`n","" -Replace "`r",""
		$cert = $cert -Replace "-----BEGIN CERTIFICATE-----", ""
		$cert = $cert -Replace "-----END CERTIFICATE-----", ""
		$cert = [Convert]::FromBase64String($cert)
		$file_hash = Get-HashFromByte($cert)

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
			"Accept-Encoding" = "binary"
		}
		if($SavePickyCertificates){
			Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers
		}
		else{
			{ Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers } | Should -Throw
		}
	}
	It 'Get cert in base64 with sha256' {
		$key_size = 2048
		$subject = "CN=test.${picky_realm}"
		$rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)

		$certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				$subject, $rsa_key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

		$csr_der = $certRequest.CreateSigningRequest()

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
			"Content-Transfer-Encoding" = "binary"
			"Content-Disposition" = "attachment"
		}

		$cert = Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $csr_der

		$cert = $cert -Replace "`n","" -Replace "`r",""
		$cert = $cert -Replace "-----BEGIN CERTIFICATE-----", ""
		$cert = $cert -Replace "-----END CERTIFICATE-----", ""
		$cert = [Convert]::FromBase64String($cert)
		$file_hash = Get-HashFromByte($cert)

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
			"Accept-Encoding" = "base64"
		}

		if($SavePickyCertificates){
			Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers
		}
		else{
			{ Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers } | Should -Throw
		}
	}
	It 'Get cert in pem with sha256' {
		$key_size = 2048
		$subject = "CN=test.${picky_realm}"
		$rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)

		$certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				$subject, $rsa_key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

		$csr_der = $certRequest.CreateSigningRequest()

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
			"Content-Transfer-Encoding" = "binary"
			"Content-Disposition" = "attachment"
		}

		$cert = Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $csr_der

		$cert = $cert -Replace "`n","" -Replace "`r",""
		$cert = $cert -Replace "-----BEGIN CERTIFICATE-----", ""
		$cert = $cert -Replace "-----END CERTIFICATE-----", ""
		$cert = [Convert]::FromBase64String($cert)
		$file_hash = Get-HashFromByte($cert)

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
		}

		if($SavePickyCertificates){
			Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers
		}
		else{
			{ Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers } | Should -Throw
		}
	}
	It 'Get default CA chain' {
		$contents = Invoke-RestMethod -Uri $picky_url/chain/ -Method 'GET' `
					-ContentType 'text/plain'

		$contents | Should -Be -Not $null
	}
	Context 'Register Certificate for John but not store on picky, John Send its signed certificate to Mary in multiple format, Mary check if the certificate is signed by is CA, and save the certificate' {
		It 'Send to Mary in base64'{
			$key_size = 2048
			$subject = "CN=test.${picky_realm}"
			$rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)

			$certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
					$subject, $rsa_key,
					[System.Security.Cryptography.HashAlgorithmName]::SHA256,
					[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

			$csr_der = $certRequest.CreateSigningRequest()

			$headers = @{
				"Authorization" = "Bearer $picky_api_key"
				"Content-Transfer-Encoding" = "binary"
				"Content-Disposition" = "attachment"
			}

			$cert = Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $csr_der

			$headers = @{
				"Authorization" = "Bearer $picky_api_key"
				"Content-Transfer-Encoding" = "base64"
				"Content-Disposition" = "attachment"
			}

			$postCert = Invoke-RestMethod -Uri $picky_url/cert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $cert
			$postCert | Should -Not -Be $null
		}
		It 'Send To Mary in Binary and check if the Certificat can be fetch fron picky'{
			$key_size = 2048
			$subject = "CN=test.${picky_realm}"
			$rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)

			$certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
					$subject, $rsa_key,
					[System.Security.Cryptography.HashAlgorithmName]::SHA256,
					[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

			$csr_der = $certRequest.CreateSigningRequest()

			$headers = @{
				"Authorization" = "Bearer $picky_api_key"
				"Content-Transfer-Encoding" = "binary"
				"Content-Disposition" = "attachment"
			}

			$cert = Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $csr_der

			$headers = @{
				"Authorization" = "Bearer $picky_api_key"
				"Content-Transfer-Encoding" = "binary"
				"Content-Disposition" = "attachment"
			}

			$cert = $cert -Replace "`n","" -Replace "`r",""
			$cert = $cert -Replace "-----BEGIN CERTIFICATE-----", ""
			$cert = $cert -Replace "-----END CERTIFICATE-----", ""
			$cert = [Convert]::FromBase64String($cert)

			$file_hash = Get-HashFromByte($cert)

			$headers = @{
				"Authorization" = "Bearer $picky_api_key"
				"Content-Transfer-Encoding" = "binary"
			}
			if($SavePickyCertificates){
				Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers
			}
			else{
				{  Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers } | Should -Throw
			}

			$postCert = Invoke-RestMethod -Uri $picky_url/cert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $cert

			$postCert | Should -Not -Be $null

			$get_cert = Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers

			$get_cert | Should -Not -Be $null
		}
		It 'Send To Mary in Json'{
			$key_size = 2048
			$subject = "CN=test.${picky_realm}"
			$rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)

			$certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
					$subject, $rsa_key,
					[System.Security.Cryptography.HashAlgorithmName]::SHA256,
					[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

			$csr_der = $certRequest.CreateSigningRequest()

			$headers = @{
				"Authorization" = "Bearer $picky_api_key"
				"Content-Transfer-Encoding" = "binary"
				"Content-Disposition" = "attachment"
			}

			$cert = Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $csr_der

			$headers = @{
				"Authorization" = "Bearer $picky_api_key"
			}
			$json = @{
				"certificate" = $cert
			} | ConvertTo-Json

			$postCert = Invoke-RestMethod -Uri $picky_url/cert/ -Method 'POST' `
                -ContentType 'application/json' `
                -Headers $headers `
                -Body $json
			$postCert | Should -Not -Be $null
		}
		it 'Register Certificate who is not signed by the CA of picky server'{

			$certificate_not_signed_by_ca = "-----BEGIN CERTIFICATE REQUEST-----
			MIICXDCCAUQCAQAwFzEVMBMGA1UEAxMMdGVzdC5XYXlrRGVuMIIBIjANBgkqhkiG
			9w0BAQEFAAOCAQ8AMIIBCgKCAQEAze5WY8kjx0V1V4p0IQCHlW3g/iXyjcSHQ4gO
			QA/8F2k8Gdy7IbcdP9ZxAvsBQOy9oC440+MV3DP9YRpK0yoA3he/P/AtFj3+yguT
			/QMfQFCL5N1v7fAxtgyW9+PqSUn9FfsI+XpMtn+dKA0opSbz6AkSfcRVXGqLJGzN
			G0LgVHCm9OF/d168MEBHYxxtLsF+DuD+axb74gG3E85lcsN4+7wA6ID99fMzabqu
			ZpYuhO8jz/gzod+8I+6WElLRb+Dwvzr+A7tVMZOYQmQOkagXcw57Vlc125mnFZ3m
			zrSQ7d3IWI2OeViDpYspEkdP3Q6yFM+IOCOOEFJpDspuXHLGowIDAQABoAAwDQYJ
			KoZIhvcNAQELBQADggEBAK5GWqCllx9arh8jaBvsqnHS8AA35Veo8EVI2KJCm+yL
			zOiTaKYZK1t5JXwRgJepV2/2/wwAd+aopna4KZXIrwdOWdo/vr4lorXvNBnxJ0du
			ktAe+ZWKcjvoAj/BztXf6BqkYeqc8wb9FCma9Fy4DcQpcQO9/7vC8upHHQMkokG+
			aumIAsk8xBpNYWct6egRy4QYUmtHipf3lJMlWBSlWfCyM9n5raB2ebqN8JdqzgLb
			Ux0WJubCRFCRMZ5UVgkaAfQp+Rj+NO5XI+zI38vJAJ/BpSWl08CEcTOQtSJ4+CWh
			UjaMTRL1GRu6lb167tvjwToZZfKxA3ogxl99kr+1Kow=
			-----END CERTIFICATE REQUEST-----"

			$certificate_not_signed_by_ca = $certificate_not_signed_by_ca -Replace "`n","" -Replace "`r",""
			$certificate_not_signed_by_ca = $certificate_not_signed_by_ca -Replace "-----BEGIN CERTIFICATE-----", ""
			$certificate_not_signed_by_ca = $certificate_not_signed_by_ca -Replace "-----END CERTIFICATE-----", ""
			$certificate_not_signed_by_ca = [Convert]::FromBase64String($cert)

			$headers = @{
				"Authorization" = "Bearer $picky_api_key"
				"Content-Transfer-Encoding" = "binary"
			}

			{ Invoke-RestMethod -Uri $picky_url/cert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $certificate_not_signed_by_ca } | Should -Throw
		}
	}
	AfterAll{
		if($Silent)
		{
			[void](& 'docker' 'stop' 'picky-mongo')
			[void](& 'docker' 'rm' 'picky-mongo')
			if($Debug){
				[void](Stop-Process -Name 'picky-server')
			}else{
				[void](& 'docker' 'stop' 'picky-server')
				[void](& 'docker' 'rm' 'picky-server')
			}
		}else{
			& 'docker' 'stop' 'picky-mongo'
			& 'docker' 'rm' 'picky-mongo'

			if($Debug){
				Stop-Process -Name 'picky-server'
			}else{
				& 'docker' 'stop' 'picky-server'
				& 'docker' 'rm' 'picky-server'
			}
		}

	}
}
