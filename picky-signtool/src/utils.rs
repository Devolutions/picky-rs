pub fn str_to_utf16_bytes(s: &str, buff: &mut Vec<u8>) {
    s.encode_utf16()
        .for_each(|word| buff.extend_from_slice(&word.to_le_bytes()));
}
