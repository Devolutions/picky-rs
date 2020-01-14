#![no_main]
use libfuzzer_sys::fuzz_target;
use picky::{
    http::{http_signature::*, *},
    key::PrivateKey,
    pem::Pem,
    signature::SignatureHashType,
};
use std::str::FromStr;

const HTTP_SIGNATURE_EXAMPLE: &str = "Signature keyId=\"my-rsa-key\", created=\"1402170695\", \
     headers=\"(request-target) (created) date\", \
     signature=\"CM3Ui6l4Z6+yYdWaX5Cz10OAqUceS53Zy/qA+e4xG5Nabe215iTlnj/sfVJ3nBaMIOj/4e\
     gxTKNDXAJbLm6nOF8zUOdJBuKQZNO1mfzrMKLsz7gc2PQI1eVxGNJoBZ40L7CouertpowQFpKyizNXqH/y\
     YBgqPEnLk+p5ISkXeHd7P/YbAAQGnSe3hnJ/gkkJ5rS6mGuu2C8+Qm68tcSGz9qwVdNTFPpji5VPxprs2J\
     2Z1vjsMVW97rsKOs8lo+qxPGfni27udledH2ZQABGZHOgZsChj59Xb3oVAA8/V3rjt5Un7gsz2AHQ6aY6o\
     ky59Rsg/CpB8gP7szjK/wrCclA==\"";

fn private_key_1() -> PrivateKey {
    let pem = include_str!("../../../test_assets/private_keys/rsa-2048-pk_1.key")
        .parse::<Pem>()
        .expect("pem 1");
    PrivateKey::from_pem(&pem).expect("private key 1")
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = HttpSignature::from_str(s);

        let signing_string = s;
        let _ = HttpSignatureBuilder::new()
            .key_id(s)
            .signature_method(&private_key_1(), SignatureHashType::RsaSha256)
            .pre_generated_signing_string(signing_string)
            .build();

        if data.len() >= 4 {
            let now = (data[0] as u64)
                + (data[1] as u64) * 2_u64.pow(8)
                + (data[2] as u64) * 2_u64.pow(16)
                + (data[3] as u64) * 2_u64.pow(24);
            let http_signature = HttpSignature::from_str(HTTP_SIGNATURE_EXAMPLE).expect("http signature");
            let _ = http_signature
                .verifier()
                .now(now)
                .signature_method(&private_key_1().to_public_key(), SignatureHashType::RsaSha256)
                .pre_generated_signing_string(s)
                .verify();
        }
    }
});
