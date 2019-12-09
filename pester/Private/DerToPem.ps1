function DerToPem([string] $label, [Byte[]] $der) {
	[OutputType('String')]

	$base64 = [Convert]::ToBase64String($der)

	$offset = 0
	$line_length = 64
	$sb = [System.Text.StringBuilder]::new()
	$sb.AppendLine("-----BEGIN $label-----") > $null
	while ($offset -lt $base64.Length) {
		$line_end = [Math]::Min($offset + $line_length, $base64.Length)
		$sb.AppendLine($base64.Substring($offset, $line_end - $offset)) > $null
		$offset = $line_end
	}
	$sb.AppendLine("-----END $label-----") > $null

	return $sb.ToString()
}

function CsrDerToPem([Byte[]] $csr_der) {
	$pem = DerToPem "CERTIFICATE REQUEST" $csr_der
	Write-Verbose "CSR: $pem"
	return $pem
}

function CertDerToPem([Byte[]] $cert_der) {
	$pem = DerToPem "CERTIFICATE" $cert_der
	Write-Verbose "Cert: $pem"
	return $pem
}
