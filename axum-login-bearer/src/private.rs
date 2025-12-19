use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit, Payload},
    Aes256Gcm,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use cookie::Key;
use rand::{RngCore, thread_rng};

use super::BearerTokenStrCodec;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// This implements [`BearerTokenStrCodec`] in a way that encrypts a session id to a bearer token in a manner
/// that should be fairly identical to a secure cookie provided by the `cookie` crate.
pub struct Private {
    // associated data
    aad: String,
    key: Key,
}

impl Private {
    /// Specify the parameters for the `Private` bearer token id codec.
    ///
    /// The `id` will be used as the associated data to prevent data swapping with other values generated
    /// using the same encryption key.
    pub fn new(id: impl ToString, key: Key) -> Self {
        Self {
            aad: id.to_string(),
            key,
        }
    }
}

// This implementation is lifted from `cookie-rs`
impl BearerTokenStrCodec for Private {
    fn encode(&self, s: &str) -> String {
        // Create a vec to hold the [nonce | value | tag].
        let s = s.as_bytes();
        let mut data = vec![0; NONCE_LEN + s.len() + TAG_LEN];

        // Split data into three: nonce, input/output, tag. Copy input.
        let (nonce, in_out) = data.split_at_mut(NONCE_LEN);
        let (in_out, tag) = in_out.split_at_mut(s.len());
        in_out.copy_from_slice(s);

        // Fill nonce piece with random data.
        let mut rng = thread_rng();
        rng.try_fill_bytes(nonce).expect("couldn't random fill nonce");
        let nonce = GenericArray::clone_from_slice(nonce);

        // Perform the actual sealing operation, using the cookie's name as
        // associated data to prevent value swapping.
        let aad = self.aad.as_bytes();
        let aead = Aes256Gcm::new(GenericArray::from_slice(self.key.encryption()));
        let aad_tag = aead.encrypt_in_place_detached(&nonce, aad, in_out)
            .expect("encryption failure!");

        // Copy the tag into the tag piece.
        tag.copy_from_slice(&aad_tag);

        // Base64 encode [nonce | encrypted value | tag].
        BASE64_STANDARD.encode(&data)
    }

    fn decode(&self, s: &str) -> Option<String> {
        // let data = BASE64_STANDARD.decode(value).map_err(|_| "bad base64 value")?;
        let data = BASE64_STANDARD.decode(s).ok()?;
        if data.len() <= NONCE_LEN {
            // return Err("length of decoded data is <= NONCE_LEN");
            return None;
        }

        let (nonce, cipher) = data.split_at(NONCE_LEN);
        let payload = Payload { msg: cipher, aad: self.aad.as_bytes() };

        let aead = Aes256Gcm::new(GenericArray::from_slice(&self.key.encryption()));
        aead.decrypt(GenericArray::from_slice(nonce), payload)
            .map_err(|_| "invalid key/nonce/value: bad seal")
            .and_then(|s| String::from_utf8(s).map_err(|_| "bad unsealed utf8"))
            .ok()
    }
}
