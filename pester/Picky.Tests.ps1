. "$PSScriptRoot/Private/Base64Url.ps1"
. "$PSScriptRoot/Private/SHA256.ps1"

Describe 'Picky tests' {
	BeforeAll {
		$picky_url = "http://127.0.0.1:12345"
		$picky_realm = "WaykDen"
		$picky_authority = "${picky_realm} Authority"
		$picky_api_key = "secret"
		$picky_backend = "mongodb"
		$picky_database_url = "mongodb://picky-mongo:27017"
		if ($picky_backend -Eq 'mongodb') {
			& 'docker' 'stop' 'picky-mongo'
			& 'docker' 'rm' 'picky-mongo'
		    & 'docker' 'run' '-d' '--network=picky' '--name' 'picky-mongo' `
		    'library/mongo:4.1-bionic'

			Start-Sleep -s 5 # wait for picky-mongo to be ready
		}

		& 'docker' 'stop' 'picky-server'
		& 'docker' 'rm' 'picky-server'
		& 'docker' 'run' '-p' '12345:12345' '-d' '--network=picky' '--name' 'picky-server' `
			'-e' "PICKY_REALM=$picky_realm" `
			'-e' "PICKY_API_KEY=$picky_api_key" `
			'-e' "PICKY_BACKEND=$picky_backend" `
			'-e' "PICKY_DATABASE_URL=$picky_database_url" `
			'devolutions/picky:3.3.0-buster-dev'
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

		Write-Host $csr_pem

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

		Write-Host $leaf_cert
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

		Write-Host $csr_pem

		Set-Content -Value $csr_pem -Path "$TestDrive/test.csr"
		$csr = Get-Content "$TestDrive/test.csr" | Out-String

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
			"Content-Transfer-Encoding" = "base64"
			"Content-Disposition" = "attachment"
		}

		Write-Host $body

		Write-Host $payload

		$cert = Invoke-RestMethod -Uri $picky_url/signcert/ -Method 'POST' `
                -ContentType 'application/pkcs10' `
                -Headers $headers `
                -Body $csr

		Set-Content -Value $cert -Path "$TestDrive/test.crt"
		$leaf_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$TestDrive/test.crt")

		Write-Host $leaf_cert
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

		Write-Host $csr_pem

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

		Write-Host $leaf_cert
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
			Write-Host $_
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

		$get_cert = Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers
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

		$get_cert = Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers

		Write-Host $get_cert
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

		$get_cert = Invoke-RestMethod -Uri "$picky_url/cert/$file_hash" -Method 'GET' `
                -Headers $headers

		Write-Host $get_cert
	}
	It 'Get default CA chain' {
		$contents = Invoke-RestMethod -Uri $picky_url/chain/ -Method 'GET' `
					-ContentType 'text/plain'

		$contents | Should -Be -Not $null
	}
	AfterAll{
		& 'docker' 'stop' 'picky-mongo'
		& 'docker' 'rm' 'picky-mongo'
		& 'docker' 'stop' 'picky-server'
		& 'docker' 'rm' 'picky-server'
	}
}
