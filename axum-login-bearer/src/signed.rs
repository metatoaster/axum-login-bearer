use base64::{Engine, prelude::BASE64_STANDARD};
use sha2::Sha256;
use hmac::{Hmac, Mac};
use cookie::Key;

use super::TokenMode;

const BASE64_DIGEST_LEN: usize = 44;

impl TokenMode {
    pub(crate) fn encode_signed(key: &Key, s: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.signing())
            .expect("key.signing() shouldn't fail to produce a good key");
        mac.update(s.as_bytes());
        let mut new_value = BASE64_STANDARD.encode(&mac.finalize().into_bytes());
        new_value.push_str(&s);
        new_value
    }

    // This is largely copied from `cookie::secure::private`
    pub(crate) fn decode_signed(key: &Key, s: &str) -> Result<String, &'static str> {
        if !s.is_char_boundary(BASE64_DIGEST_LEN) {
            return Err("missing or invalid digest");
        }

        // Split [MAC | original-value] into its two parts.
        let (digest_str, value) = s.split_at(BASE64_DIGEST_LEN);
        let digest = BASE64_STANDARD.decode(digest_str).map_err(|_| "bad base64 digest")?;

        // Perform the verification.
        let mut mac = Hmac::<Sha256>::new_from_slice(key.signing())
            .expect("key.signing() shouldn't fail to produce a good key");
        mac.update(value.as_bytes());
        mac.verify_slice(&digest)
            .map(|_| value.to_string())
            .map_err(|_| "provided value failed the signature check")
    }
}
