. "$PSScriptRoot/Private/Base64Url.ps1"

Describe 'Picky tests' {
	BeforeAll {
		$picky_url = "http://127.0.0.1:12345"
		$picky_realm = "contoso.local"
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
			'devolutions/picky:3.0.0-buster'

		Start-Sleep -s 5 # wait for picky-server to be ready
	}

	It 'checks health' {
		Write-Host "$picky_url/health"
		$request = Invoke-WebRequest -Uri $picky_url/health -Method 'GET' -ContentType 'text/plain'
		$request.StatusCode | Should -Be 200
	}

	It 'gets the CA chain' {
		$authority_base64 = ConvertTo-Base64Url $picky_authority
		$contents = Invoke-RestMethod -Uri $picky_url/chain/$authority_base64 -Method 'GET' `
			-ContentType 'text/plain'

		$ca_chain = @()
		# https://stackoverflow.com/questions/45884754/powershell-extract-multiple-occurrences-in-multi-lines
		$contents | Select-String  -Pattern '(?smi)^-{2,}BEGIN CERTIFICATE-{2,}.*?-{2,}END CERTIFICATE-{2,}' `
			-Allmatches | ForEach-Object {$_.Matches} | ForEach-Object { $ca_chain += $_.Value }

		$ca_chain.Count | Should -Be 2
		Set-Content -Value $ca_chain[0] -Path ".\intermediate_ca.pem"
		Set-Content -Value $ca_chain[1] -Path ".\root_ca.pem"

		$root_ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("root_ca.pem")
		$intermediate_ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("intermediate_ca.pem")

		$intermediate_ca.Subject | Should -Be "CN=${picky_realm} Authority"
		$intermediate_ca.Issuer | Should -Be "CN=${picky_realm} Root CA"

		$root_ca.Subject | Should -Be "CN=${picky_realm} Root CA"
		$root_ca.Issuer | Should -Be "CN=${picky_realm} Root CA"
	}

	It 'signs certificates' {
		# https://www.digicert.com/ssl-support/openssl-quick-reference-guide.htm
		& 'openssl' 'genrsa' '-out' 'test.key' '2048'
		& 'openssl' 'rsa' '-text' '-in' 'test.key' '-noout'
		& 'openssl' 'req' '-new' '-key' 'test.key' '-out' 'test.csr' `
			'-subj' "/CN=test.${picky_realm}"
		& 'openssl' 'req' '-text' '-in' 'test.csr' '-noout' '-verify'

		$csr = Get-Content ".\test.csr" | Out-String

		$headers = @{
			"Authorization" = "Bearer $picky_api_key"
		}

		$payload = [PSCustomObject]@{
			ca="$picky_authority"
			csr="$csr"
		} | ConvertTo-Json

		Write-Host $payload

		$cert = Invoke-RestMethod -Uri $picky_url/signcert -Method 'POST' `
			-Headers $headers `
			-ContentType 'application/json' `
			-Body $payload

		Set-Content -Value $cert -Path ".\test.crt"
		$leaf_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("test.crt")

		Write-Host $leaf_cert
		$leaf_cert.Subject | Should -Be "CN=test.${picky_realm}"
		$leaf_cert.Issuer | Should -Be "CN=${picky_realm} Authority"
	}
}
