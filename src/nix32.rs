//! Nix's little-endian base32 (alphabet without e, o, u, t).

const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

pub fn encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let output_len = (input.len() * 8 - 1) / 5 + 1;
    let mut out = vec![0u8; output_len];
    for i in (0..output_len).rev() {
        let bit = i * 5;
        let byte_index = bit / 8;
        let bit_offset = bit % 8;
        let mut value = u16::from(input[byte_index]) >> bit_offset;
        if byte_index + 1 < input.len() {
            value |= u16::from(input[byte_index + 1]) << (8 - bit_offset);
        }
        out[output_len - 1 - i] = ALPHABET[(value & 0x1f) as usize];
    }
    String::from_utf8(out).expect("nix32 alphabet is ascii")
}

pub fn is_hash_part(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| ALPHABET.contains(&b))
}

pub fn is_nar_hash(value: &str) -> bool {
    value.len() == 52 && value.bytes().all(|b| ALPHABET.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_empty_sha256() {
        let digest = hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(
            encode(&digest),
            "0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73"
        );
    }

    fn hex_decode(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
}
