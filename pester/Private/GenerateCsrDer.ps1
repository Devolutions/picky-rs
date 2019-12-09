function GenerateCsrDer([string] $subject) {
    [OutputType('Byte[]')]

    $rsa_key = [System.Security.Cryptography.RSA]::Create(2048)
    $cert_request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $subject, $rsa_key,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    $csr_der = $cert_request.CreateSigningRequest()

    return $csr_der
}
