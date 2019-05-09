use base64::{encode as base64_encode, decode as base64_decode};
use multihash::{encode, decode, Hash, to_hex};

const PICKY_HASH: Hash =  Hash::SHA2256;
pub const CERT_PREFIX: &str = "-----BEGIN CERTIFICATE-----";
pub const CERT_SUFFIX: &str = "-----END CERTIFICATE-----";
pub const KEY_PREFIX: &str = "-----BEGIN RSA PRIVATE KEY-----";
pub const KEY_SUFFIX: &str = "-----END RSA PRIVATE KEY-----";
const SHA256_MULTIHASH_PREFIX: &str = "1220";

pub fn der_to_pem(der: &[u8]) -> String{
    base64_encode(der)
}

pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, String>{
    let mut pem = strip_pem_tag(&pem);
    pem = pem.replace(" ", "");
    match base64_decode(pem.as_bytes()){
        Ok(d) => { return Ok(d);},
        Err(e) => { return Err(e.to_string()); }
    }
}

pub fn strip_pem_tag(pem: &str) -> String {
    let mut pem = pem.replace("\\n", "");
    let mut pem = pem.replace("\n", "");

    if pem.contains(CERT_PREFIX){
        pem = pem.replace(CERT_PREFIX, "")
            .replace(CERT_SUFFIX, "");
    } else {
        pem = pem.replace(KEY_PREFIX, "")
            .replace(KEY_SUFFIX, "");
    }

    pem
}

pub fn multihash_encode(value: &str) -> Result<String, String> {
    match encode(PICKY_HASH, strip_pem_tag(value).as_bytes()){
        Ok(result) => Ok(to_hex(&result)),
        Err(e) => Err(e.to_string())
    }
}

pub fn multihash_decode(value: &[u8]) -> Result<Vec<u8>, String> {
    match decode(value) {
        Ok(result) => Ok(result.digest.to_vec()),
        Err(e) => Err(e.to_string())
    }
}

pub fn sha256_to_multihash(hash: &str) -> Result<String, String> {
    let hash = format!("{}{}", SHA256_MULTIHASH_PREFIX, hash);
    Ok(hash)
}

pub fn fix_pem(pem: &str) -> String {
    let mut pem = pem.clone()
        .replace("\n", "")
        .replace(CERT_PREFIX, "")
        .replace(CERT_SUFFIX, "")
        .replace(" ", "");

    let mut fixed_pem = String::default();

    while pem.len()/64 > 0{
        let s = pem.split_at(63);
        fixed_pem.push_str(&format!("{}{}", s.0, "\n"));
        pem = s.1.to_string();
    }

    fixed_pem.push_str(&format!("{}{}", pem, "\n"));
    let fixed_pem = format!("{}{}{}", format!("{}{}", CERT_PREFIX, "\n"), fixed_pem, format!("{}{}", CERT_SUFFIX, "\n"));
    fixed_pem
}

#[cfg(test)]
mod tests{
    use super::*;
    use regex::Regex;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\n\
    MIIEwTCCAqmgAwIBAgIAMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNVBAMMB0NOPXRl\n\
    c3QwHhcNMTkwMTAxMDAwMDAwWhcNMjAwMTAxMDAwMDAwWjASMRAwDgYDVQQDDAdD\n\
    Tj10ZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAspOfaKAL/7VH\n\
    osLf/BSLiflNzv/j+BXE9xYoaSAjDWlXgkAm7RLPhY6M04iWg858enKdl8f4fgZ6\n\
    xDD0LAYYvM0qQ+eTcIFrEm8rZmvQkfSQaWBsqs5ylChYFBMj0w9tMdrdi2VMUR7p\n\
    U9oLlsOH1RpxI7c5ecH1xK4cNK+utRdhykRpnOmsPUXWPMDrRP0vwQ97KtvX/8r6\n\
    r+mQOqf2Ti5p6MJMmaYeuVI4tT59ahnIHNZk3QUN1nLruByOXrASWnY0sN5cBfzq\n\
    U9KUElyczIW3b/fVp7NjuGU+3bTO2Uda2vGzZfUU/VU/nLSfvSjtGoApI8/EB6Uw\n\
    ul1DFiiB7LtZ37YITzv5ydf4CQIIVB6GtMXMU78fheKJQHruH5BTErvSGfA/UAnA\n\
    wPoY6I2/4x9obgxtjokXQHh1SD0fXDD4x8+KEb6T5HzIRQN2N83lbuQi9PcLJqlw\n\
    4CTANxY1078Kao1CaVeIupaKVznrYtV0D0pXg5gsyGCSxT8RLPI3xNABlBer9911\n\
    NZaz7r5LZZSXHYbvEWcBVeLFw3SvwCO7opCkISrZNd/3wYe1GZSZRdPbX5G7KVB/\n\
    J5dp4MKbz6F/RWAOV8YWV8CFf+p4fRcCUUzcZ9XGFMLFJVELfFJDstTATDsKBYdy\n\
    +L8jfTULdRPUFYid2egSEtQS69WNW+cCAwEAAaMjMCEwDwYDVR0TBAgwBgEB/wIB\n\
    ADAOBgNVHQ8BAf8EBAMCAa4wDQYJKoZIhvcNAQELBQADggIBAGEbKEjRiGR3yD2r\n\
    0vrOJlUmWml7rQOvRcIE8G8+9NJyvwuofAeyrXZkLXKhEgQ9whExygajwm2CU5/S\n\
    eFAosRsL/vLGqUUh1LBHAG/Yo/mX/Rw7M4g0/aQHWr1DdxQUKm5cUnz52DvdhER3\n\
    W/JoeiMByA+2tJPzzn0UMb1Ewl0FDwuBfnc9qzNeq4iUpr1EP1DIbT3B3aln7YHY\n\
    KtDIJdE5gf32IKZSmmSG5y4NeVwyUC30xYSrcgTE+bTTd8YPbvwJOXgaZEfC2Ctr\n\
    2F0X5Aq3aDPKYbz10/FLxK74fSKsh0sC4pfQeZ/1oYH0LNzP3WRbiSi+AlF5qShp\n\
    1eWpGiZZBvYKNs5p0n5AS0+Q2zrhP15RtFuhNd6Dr+6tQjvOIFssD491CH8B6oiQ\n\
    Rd4UHn9cHT2SfuUlEXkLd1oqZkgmn7xhXgLQ2ExoFJdGdl1rZsRlBu3f1OlLfVfS\n\
    5ZSHohHy654/4gADytc0k5dQOI1qVLfacCykuzspBBs5P47LVuJaCSMOaKmvEIZR\n\
    nNd168xyJYPOTLzYjSDari1Weo8kzP51i1osSP5JvtNeABqGdxOgeqHtMcc963iy\n\
    6Gp2fAYCjFf2wRNA/sr156Al788MhiRMAMyTF7hP7NI8qmHsoGrUqxPuRAMLO8KX\n\
    FZrYypwmYQ0gvQoGryArLnyseHBm\n-----END CERTIFICATE-----";

    const DER: [u8; 1221] = [48, 130, 4, 193, 48, 130, 2, 169, 160, 3, 2, 1, 2, 2, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 18, 49, 16, 48, 14, 6, 3, 85, 4, 3, 12, 7, 67, 78, 61, 116, 101, 115, 116, 48, 30, 23, 13, 49, 57, 48, 49, 48, 49, 48, 48, 48, 48, 48, 48, 90, 23, 13, 50, 48, 48, 49, 48, 49, 48, 48, 48, 48, 48, 48, 90, 48, 18, 49, 16, 48, 14, 6, 3, 85, 4, 3, 12, 7, 67, 78, 61, 116, 101, 115, 116, 48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130, 2, 1, 0, 178, 147, 159, 104, 160, 11, 255, 181, 71, 162, 194, 223, 252, 20, 139, 137, 249, 77, 206, 255, 227, 248, 21, 196, 247, 22, 40, 105, 32, 35, 13, 105, 87, 130, 64, 38, 237, 18, 207, 133, 142, 140, 211, 136, 150, 131, 206, 124, 122, 114, 157, 151, 199, 248, 126, 6, 122, 196, 48, 244, 44, 6, 24, 188, 205, 42, 67, 231, 147, 112, 129, 107, 18, 111, 43, 102, 107, 208, 145, 244, 144, 105, 96, 108, 170, 206, 114, 148, 40, 88, 20, 19, 35, 211, 15, 109, 49, 218, 221, 139, 101, 76, 81, 30, 233, 83, 218, 11, 150, 195, 135, 213, 26, 113, 35, 183, 57, 121, 193, 245, 196, 174, 28, 52, 175, 174, 181, 23, 97, 202, 68, 105, 156, 233, 172, 61, 69, 214, 60, 192, 235, 68, 253, 47, 193, 15, 123, 42, 219, 215, 255, 202, 250, 175, 233, 144, 58, 167, 246, 78, 46, 105, 232, 194, 76, 153, 166, 30, 185, 82, 56, 181, 62, 125, 106, 25, 200, 28, 214, 100, 221, 5, 13, 214, 114, 235, 184, 28, 142, 94, 176, 18, 90, 118, 52, 176, 222, 92, 5, 252, 234, 83, 210, 148, 18, 92, 156, 204, 133, 183, 111, 247, 213, 167, 179, 99, 184, 101, 62, 221, 180, 206, 217, 71, 90, 218, 241, 179, 101, 245, 20, 253, 85, 63, 156, 180, 159, 189, 40, 237, 26, 128, 41, 35, 207, 196, 7, 165, 48, 186, 93, 67, 22, 40, 129, 236, 187, 89, 223, 182, 8, 79, 59, 249, 201, 215, 248, 9, 2, 8, 84, 30, 134, 180, 197, 204, 83, 191, 31, 133, 226, 137, 64, 122, 238, 31, 144, 83, 18, 187, 210, 25, 240, 63, 80, 9, 192, 192, 250, 24, 232, 141, 191, 227, 31, 104, 110, 12, 109, 142, 137, 23, 64, 120, 117, 72, 61, 31, 92, 48, 248, 199, 207, 138, 17, 190, 147, 228, 124, 200, 69, 3, 118, 55, 205, 229, 110, 228, 34, 244, 247, 11, 38, 169, 112, 224, 36, 192, 55, 22, 53, 211, 191, 10, 106, 141, 66, 105, 87, 136, 186, 150, 138, 87, 57, 235, 98, 213, 116, 15, 74, 87, 131, 152, 44, 200, 96, 146, 197, 63, 17, 44, 242, 55, 196, 208, 1, 148, 23, 171, 247, 221, 117, 53, 150, 179, 238, 190, 75, 101, 148, 151, 29, 134, 239, 17, 103, 1, 85, 226, 197, 195, 116, 175, 192, 35, 187, 162, 144, 164, 33, 42, 217, 53, 223, 247, 193, 135, 181, 25, 148, 153, 69, 211, 219, 95, 145, 187, 41, 80, 127, 39, 151, 105, 224, 194, 155, 207, 161, 127, 69, 96, 14, 87, 198, 22, 87, 192, 133, 127, 234, 120, 125, 23, 2, 81, 76, 220, 103, 213, 198, 20, 194, 197, 37, 81, 11, 124, 82, 67, 178, 212, 192, 76, 59, 10, 5, 135, 114, 248, 191, 35, 125, 53, 11, 117, 19, 212, 21, 136, 157, 217, 232, 18, 18, 212, 18, 235, 213, 141, 91, 231, 2, 3, 1, 0, 1, 163, 35, 48, 33, 48, 15, 6, 3, 85, 29, 19, 4, 8, 48, 6, 1, 1, 255, 2, 1, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 174, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 2, 1, 0, 97, 27, 40, 72, 209, 136, 100, 119, 200, 61, 171, 210, 250, 206, 38, 85, 38, 90, 105, 123, 173, 3, 175, 69, 194, 4, 240, 111, 62, 244, 210, 114, 191, 11, 168, 124, 7, 178, 173, 118, 100, 45, 114, 161, 18, 4, 61, 194, 17, 49, 202, 6, 163, 194, 109, 130, 83, 159, 210, 120, 80, 40, 177, 27, 11, 254, 242, 198, 169, 69, 33, 212, 176, 71, 0, 111, 216, 163, 249, 151, 253, 28, 59, 51, 136, 52, 253, 164, 7, 90, 189, 67, 119, 20, 20, 42, 110, 92, 82, 124, 249, 216, 59, 221, 132, 68, 119, 91, 242, 104, 122, 35, 1, 200, 15, 182, 180, 147, 243, 206, 125, 20, 49, 189, 68, 194, 93, 5, 15, 11, 129, 126, 119, 61, 171, 51, 94, 171, 136, 148, 166, 189, 68, 63, 80, 200, 109, 61, 193, 221, 169, 103, 237, 129, 216, 42, 208, 200, 37, 209, 57, 129, 253, 246, 32, 166, 82, 154, 100, 134, 231, 46, 13, 121, 92, 50, 80, 45, 244, 197, 132, 171, 114, 4, 196, 249, 180, 211, 119, 198, 15, 110, 252, 9, 57, 120, 26, 100, 71, 194, 216, 43, 107, 216, 93, 23, 228, 10, 183, 104, 51, 202, 97, 188, 245, 211, 241, 75, 196, 174, 248, 125, 34, 172, 135, 75, 2, 226, 151, 208, 121, 159, 245, 161, 129, 244, 44, 220, 207, 221, 100, 91, 137, 40, 190, 2, 81, 121, 169, 40, 105, 213, 229, 169, 26, 38, 89, 6, 246, 10, 54, 206, 105, 210, 126, 64, 75, 79, 144, 219, 58, 225, 63, 94, 81, 180, 91, 161, 53, 222, 131, 175, 238, 173, 66, 59, 206, 32, 91, 44, 15, 143, 117, 8, 127, 1, 234, 136, 144, 69, 222, 20, 30, 127, 92, 29, 61, 146, 126, 229, 37, 17, 121, 11, 119, 90, 42, 102, 72, 38, 159, 188, 97, 94, 2, 208, 216, 76, 104, 20, 151, 70, 118, 93, 107, 102, 196, 101, 6, 237, 223, 212, 233, 75, 125, 87, 210, 229, 148, 135, 162, 17, 242, 235, 158, 63, 226, 0, 3, 202, 215, 52, 147, 151, 80, 56, 141, 106, 84, 183, 218, 112, 44, 164, 187, 59, 41, 4, 27, 57, 63, 142, 203, 86, 226, 90, 9, 35, 14, 104, 169, 175, 16, 134, 81, 156, 215, 117, 235, 204, 114, 37, 131, 206, 76, 188, 216, 141, 32, 218, 174, 45, 86, 122, 143, 36, 204, 254, 117, 139, 90, 44, 72, 254, 73, 190, 211, 94, 0, 26, 134, 119, 19, 160, 122, 161, 237, 49, 199, 61, 235, 120, 178, 232, 106, 118, 124, 6, 2, 140, 87, 246, 193, 19, 64, 254, 202, 245, 231, 160, 37, 239, 207, 12, 134, 36, 76, 0, 204, 147, 23, 184, 79, 236, 210, 60, 170, 97, 236, 160, 106, 212, 171, 19, 238, 68, 3, 11, 59, 194, 151, 21, 154, 216, 202, 156, 38, 97, 13, 32, 189, 10, 6, 175, 32, 43, 46, 124, 172, 120, 112, 102];

    #[test]
    fn test_decode_encode(){
        let p = PEM.replace("\n", "");
        let re = Regex::new(r"-----BEGIN CERTIFICATE-----\s*([\w\\/+]+)\s*-----END CERTIFICATE-----").unwrap();

        let mat = re.captures(&p).unwrap()[1].to_string();
        let p = re.captures(&p).unwrap()[0].to_string();

        let decoded = base64_decode(&mat).unwrap();

        let encoded = base64_encode(&decoded);
        let encoded = format!("{}{}{}", "-----BEGIN CERTIFICATE-----", encoded, "-----END CERTIFICATE-----");

        assert_eq!(encoded, p);
        assert_eq!(decoded, DER.to_vec());
    }

    #[test]
    fn test_der(){
        use mbedtls::hash::{Md, Type};

        let p = "MIIFFzCCAv+gAwIBAgIAMA0GCSqGSIb3DQEBCwUAMB0xGzAZBgNVBAMMEm15X2Rlbi5sb2wgUm9vdCBDQTAeFw0xOTA0MjYxOTU3MzRaFw0yOTA0MjMxOTU3MzRaMB0xGzAZBgNVBAMMEm15X2Rlbi5sb2wgUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMeocTRad5IZ8chKiGMtIkmzxigUwTB6YEdsaTimfsr3qZCsFd+eRHmevlamAl8SuNCzc9vzygFRgMDU4Cg15yKB5p7UGKaktBGPLEcpQpQ2bIFKP4QSrsEIDGibMhY9NUmU5RWABpD9Q0GvWYorIl1aVnBNL8fectPFwTyM+XYhezXxcc5p6LkVGhoSi25ZdWW2pZH2bdUqFEqyR/fG1IJiXjFXriYUy+QpOySWu2mbWbBaom0QhKJBXavywEr9Nz6ipBKWJkm6owwUUoPLvPqp9VaQk+10dwbQxLuLSaV1CwSiu0uv7PJKqpTOtIYDqIdA+G5/avQkaYoqIhoaoWRtZK8cyd6wdyBp8djBWrBO8ioKZsc8kQ/46TgaBkOYWpT/XLbWWNlO3dRl/ZbBcaAapPl1gsmqL4ZhqU+X/mG/VRky09Nuzfkp7vQ3dBjOFY7HDZfwPl8zhJNomqv7rfA75Al8g7HyikQYkn5JUb0kJ1jOSsvmuoeuVTW8f1BsPUcLURXpCabPE+DqdTvdS72GLhjwN76TiXC3GpL5wnGH8VBJpAANHIxXcyDSHcIISDHM3tEkfZo1zwLWokK4SXf4PWTfPIw3ibvHs0+0u67amtOF8nkw8uMyANCnI+KUrLfZ2Zuf46dKulmamqzY8M01hyk+nQwbcSeft8zyxZ61AgMBAAGjYzBhMA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgGuMB0GA1UdDgQWBBT4Me4n9TU9enVKqZfYlXS8kTQvaTAfBgNVHSMEGDAWgBT4Me4n9TU9enVKqZfYlXS8kTQvaTANBgkqhkiG9w0BAQsFAAOCAgEAIOb304jnSyDawALJS3DNyu9PdjKb8H0OOLxbm5SBwzx4X6xBJGdQyagIoaBsyPfDMKOxx8h+kJkbFhT7wZRSWFJqRBSVpINN01bWeANZQEtCRDbbzK9p3irbGK01J3lzGeGP81lZS3QBoR2gIyPvZdw3Heh8NBMBXtfmf2tx645R4+EeOlITvOBavZC+BHh3KqKylSe2PG/v9N/8piD2171XbQYqo1tEnUgu9JutvilALeCPrc5QtEanZPw+xKYn7/MXwduHOy9acWLR863gezCWflL6bmy5YauFZEouY36+N2Za7gfnueNHuahTGymEZI+vsiT0jvCBYFGlv0Oupky5jtfSEXIyYAqQ6jw6f5rWjI9yabHHjA7kpgnT3p/9r67CivB1fMqVi99z7L0GQQbwLp5cgMYJHAfgMNMNggtrDtnPR4Zolk1MZNerLiX82E0/ObT2k0gwkykfYhILXeA/cITi6+1O64+iG9OKflTV4tS7lvKFkYUgWugR4BKKIDG5YKz4DA72LNgnP8ssLNxgaT0yf/EJNO/1ui3a6LkOG1jqiA5pEOM78mC+aG83FM72dXqnuLjy5SXBHshyUSnTClTbXpAp0sAouFctaPWRcd9bDVkII59nL5PJCWkBYQFPLnnL/8jMFnSlZxis+A1AEnYmABMFX3ei6nZW9AA=";
        let d = pem_to_der(p).unwrap();

        let mut res: [u8; 2048] = [0u8; 2048];
        let hash = Md::hash(Type::Sha256, &d, &mut res).unwrap();
        let hex = to_hex(&res[0..hash]);

        assert_eq!(hex, "6a6eba242e7a03c59375634409d720a60750e5cd74c539ed8d52c9343b1abed4");

    }
}