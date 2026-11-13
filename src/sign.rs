//! Binary-cache signatures compatible with Nix's libsodium Ed25519 keys.
//!
//! A secret key file is `name:<base64>`, where the decoded payload is 64
//! bytes: the 32-byte seed followed by the 32-byte public key. The signed
//! payload is the fingerprint
//! `1;<store-path>;sha256:<nix32>;<nar-size>;<comma-separated full refs>`.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

#[cfg(test)]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Clone)]
pub struct SecretKey {
    pub name: String,
    key: SigningKey,
}

impl SecretKey {
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (name, encoded) = text
            .split_once(':')
            .ok_or_else(|| "secret key is missing a ':' separator".to_string())?;
        if name.is_empty() {
            return Err("secret key name is empty".to_string());
        }
        let bytes = BASE64
            .decode(encoded.trim())
            .map_err(|err| format!("secret key is not valid base64: {err}"))?;
        if bytes.len() != 64 {
            return Err(format!(
                "secret key must be 64 bytes after base64, got {}",
                bytes.len()
            ));
        }
        let key_bytes: [u8; 64] = bytes.try_into().unwrap();
        let key = SigningKey::from_keypair_bytes(&key_bytes)
            .map_err(|err| format!("secret key is not a valid ed25519 keypair: {err}"))?;
        Ok(Self {
            name: name.to_string(),
            key,
        })
    }

    pub fn sign(&self, fingerprint: &str) -> String {
        let signature = self.key.sign(fingerprint.as_bytes());
        format!("{}:{}", self.name, BASE64.encode(signature.to_bytes()))
    }

    #[cfg(test)]
    pub fn public_key(&self) -> String {
        format!(
            "{}:{}",
            self.name,
            BASE64.encode(self.key.verifying_key().to_bytes())
        )
    }
}

pub fn fingerprint(store_path: &str, nar_hash_nix32: &str, nar_size: u64, references: &[String]) -> String {
    let mut out = format!("1;{store_path};sha256:{nar_hash_nix32};{nar_size};");
    for (index, reference) in references.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(reference);
    }
    out
}

#[cfg(test)]
pub fn verify(public_key_b64: &str, signature_b64: &str, fingerprint: &[u8]) -> bool {
    let Ok(public_bytes) = BASE64.decode(public_key_b64) else {
        return false;
    };
    let Ok(public_bytes) = <[u8; 32]>::try_from(public_bytes) else {
        return false;
    };
    let Ok(signature_bytes) = BASE64.decode(signature_b64) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&public_bytes) else {
        return false;
    };
    key.verify_strict(fingerprint, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_matches_nix() {
        let refs = vec![
            "/nix/store/0jqd0rlxzra1rs38rdxl43yh6rxchgc6-curl-7.82.0".to_string(),
            "/nix/store/6w8g7njm4mck5dmjxws0z1xnrxvl81xa-glibc-2.34-115".to_string(),
            "/nix/store/j5jxw3iy7bbz4a57fh9g2xm2gxmyal8h-zlib-1.2.12".to_string(),
            "/nix/store/yxvjs9drzsphm9pcf42a4byzj1kb9m7k-openssl-1.1.1n".to_string(),
        ];
        assert_eq!(
            fingerprint(
                "/nix/store/syd87l2rxw8cbsxmxl853h0r6pdwhwjr-curl-7.82.0-bin",
                "1b4sb93wp679q4zx9k1ignby1yna3z7c4c2ri3wphylbc2dwsys0",
                196040,
                &refs,
            ),
            "1;/nix/store/syd87l2rxw8cbsxmxl853h0r6pdwhwjr-curl-7.82.0-bin;sha256:1b4sb93wp679q4zx9k1ignby1yna3z7c4c2ri3wphylbc2dwsys0;196040;/nix/store/0jqd0rlxzra1rs38rdxl43yh6rxchgc6-curl-7.82.0,/nix/store/6w8g7njm4mck5dmjxws0z1xnrxvl81xa-glibc-2.34-115,/nix/store/j5jxw3iy7bbz4a57fh9g2xm2gxmyal8h-zlib-1.2.12,/nix/store/yxvjs9drzsphm9pcf42a4byzj1kb9m7k-openssl-1.1.1n"
        );
    }

    #[test]
    fn public_key_matches_nix() {
        let output = std::process::Command::new("nix")
            .args(["key", "generate-secret", "--key-name", "test-cache"])
            .output();
        let Ok(output) = output else {
            return;
        };
        if !output.status.success() {
            return;
        }
        let secret = String::from_utf8(output.stdout).unwrap();
        let parsed = SecretKey::parse(&secret).unwrap();
        let mut child = std::process::Command::new("nix")
            .args(["key", "convert-secret-to-public"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(secret.as_bytes())
            .unwrap();
        let done = child.wait_with_output().unwrap();
        assert!(
            done.status.success(),
            "nix key convert failed: {}",
            String::from_utf8_lossy(&done.stderr)
        );
        let expected = String::from_utf8(done.stdout).unwrap();
        assert_eq!(parsed.public_key(), expected.trim());
    }

    #[test]
    fn verifies_a_real_nix_cache_signature() {
        let fingerprint = b"1;/nix/store/syd87l2rxw8cbsxmxl853h0r6pdwhwjr-curl-7.82.0-bin;sha256:1b4sb93wp679q4zx9k1ignby1yna3z7c4c2ri3wphylbc2dwsys0;196040;/nix/store/0jqd0rlxzra1rs38rdxl43yh6rxchgc6-curl-7.82.0,/nix/store/6w8g7njm4mck5dmjxws0z1xnrxvl81xa-glibc-2.34-115,/nix/store/j5jxw3iy7bbz4a57fh9g2xm2gxmyal8h-zlib-1.2.12,/nix/store/yxvjs9drzsphm9pcf42a4byzj1kb9m7k-openssl-1.1.1n";
        assert!(verify(
            "6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
            "TsTTb3WGTZKphvYdBHXwo6weVILmTytUjLB+vcX89fOjjRicCHmKA4RCPMVLkj6TMJ4GMX3HPVWRdD1hkeKZBQ==",
            fingerprint,
        ));
    }
}
