Describe 'Picky tests' {
	BeforeAll {
		$picky_url = "http://127.0.0.1:12345"
		$picky_realm = "contoso.local"
		$picky_api_key = "secret"
		$picky_backend = "mongodb"
		$picky_database_url = "mongodb://picky-mongo:27017"

		& 'docker' 'stop' 'picky-mongo'
		& 'docker' 'rm' 'picky-mongo'
		& 'docker' 'run' '-d' '--network=picky' '--name' 'picky-mongo' `
			'library/mongo:4.1-bionic'

		Start-Sleep -s 5 # wait for picky-mongo to be ready

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
}
