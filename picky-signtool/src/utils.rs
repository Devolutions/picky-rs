pub fn str_to_utf16_bytes(s: &str, buff: &mut Vec<u8>) {
    buff.extend(s.encode_utf16().flat_map(|word| word.to_le_bytes()))
}
