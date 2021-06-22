// Author:
// - Yuzo <yuzonakai@gmail.com>

// Ed25519 interface.

#![allow(non_snake_case)]

use crate::curve25519::group_element::*;

use crate::constants::*;
use crate::curve25519::scalar_ops::*;
use crate::errors::*;
use crate::secret::*;
use crate::signature::*;

use sha2::{Digest, Sha512};

/// The Ed25519 public key.
#[derive(Copy, Clone)]
pub struct PublicKey(pub(crate) [u8; PublicKeySize]);

const L: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

/// Check if the signature s is within the group order L.
fn check_lt_l(s: &[u8]) -> bool {
    let mut c: u8 = 0;
    let mut n: u8 = 1;

    let mut i = 31;
    loop {
        c |= ((((s[i] as i32) - (L[i] as i32)) >> 8) as u8) & n;
        n &= ((((s[i] ^ L[i]) as i32) - 1) >> 8) as u8;
        if i == 0 {
            break;
        } else {
            i -= 1;
        }
    }
    c == 0
}

impl PublicKey {
    /// Generates `PublicKey` by providing a `SecretKey`.
    ///
    /// Returns the `PublicKey` counterpart.
    pub(crate) fn generate(pr: &SecretKey) -> PublicKey {
        // Hash the 32-byte private key using SHA-512, storing the digest in
        // a 64-octet large buffer h. Only the lower 32 bytes are
        // used for generating the public key.
        let h = {
            let mut hash = Sha512::default();
            hash.input(pr.0);
            let mut output = hash.result();
            // Lowest 3 bits of the first octet are cleared
            output[0] &= 248;
            // Highest bit of the last octet is cleared
            output[31] &= 63;
            // Second highest bit of the last octet is set
            output[31] |= 64;
            output
        };

        // Scalar multiplication: h * B.
        let point = Precomp::scalar_multiply(&h[0..32]);
        // Encode P2 point y coordinate.
        let public: [u8; 32] = point.encode();

        PublicKey(public)
    }

    /// Converts `PublicKey` into a 32-byte array.
    ///
    /// Returns a 32-byte array `[u8; 32]`.
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate ed25519_fun;
    ///
    /// use ed25519_fun::{Keypair, PublicKey};
    ///
    /// fn main() {
    ///     let keypair = Keypair::generate();
    ///     let public_key = keypair.public;
    ///     let bytes: [u8; 32] = public_key.as_bytes();
    ///     ...
    ///     ...
    /// }
    /// ```
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Constructs `PublicKey` from a slice.
    ///
    /// Returns `Ok(PublicKey)` if `bytes` is 32 bytes long and `Err` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate ed25519_fun;
    ///
    /// use ed25519_fun::{Keypair, PublicKey};
    ///
    /// fn main() {
    ///     let keypair = Keypair::generate();
    ///     let public_key = keypair.public;
    ///     let bytes: [u8; 32] = public_key.as_bytes();
    ///     let public_key_from_bytes: PublicKey = PublicKey::from_bytes(&bytes).unwrap();
    ///     ...
    ///     ...
    /// }
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut public = [0u8; PublicKeySize];

        if bytes.len() != PublicKeySize {
            return Err(Error::InvalidPublicKey);
        }

        public.copy_from_slice(bytes);

        Ok(PublicKey(public))
    }

    /// Verifies a signature with this `PublicKey`.
    ///
    /// Returns `Ok(())` if the signature is valid and `Err` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate ed25519_fun;
    ///
    /// use ed25519_fun::{Keypair, Signature};
    ///
    /// fn main() {
    ///     let message: &[u8] = b"";
    ///     let keypair = Keypair::generate();
    ///     let secret_key = keypair.secret;
    ///     let public_key = keypair.public;
    ///     let signature: Signature = secret_key.sign(&public_key, message);
    ///     let _signok = public_key.verify(message, &signature);
    ///     ...
    ///     ...
    /// }
    /// ```
    pub fn verify(&self, message: &[u8], sig: &Signature) -> Result<(), Error> {
        let signature = sig.as_bytes();
        let s = &signature[32..64];

        if check_lt_l(s) {
            return Err(Error::InvalidSignature);
        }

        // Try to decode the public key into a P3 point.
        // Verification fails if decoding fails.
        let A = match P3::decode(self.0) {
            Some(point) => point,
            None => {
                return Err(Error::InvalidSignature);
            }
        };

        // Compute SHA512(R || A || PH(M)), and interpret the
        // 64-octet digest as a little-endian integer k.
        let mut k = {
            let mut hash = Sha512::default();
            hash.input(&signature[0..32]);
            hash.input(&self.0);
            hash.input(&message);
            hash.result()
        };
        reduce(&mut k);

        // Check the group equation [s]B = R + [k]A'.
        // Perform [s]B + [k]A'.
        let eq = P2::double_scalar_multiply_vartime(&k[..], s, A);
        // Check [s]B + [k]A' == R?
        if eq
            .encode()
            .as_ref()
            .iter()
            .zip(signature.iter())
            .fold(0, |acc, (x, y)| acc | (x ^ y))
            == 0
        {
            Ok(())
        } else {
            return Err(Error::SignatureMismatch);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::*;

    #[test]
    fn as_from_slices_public_key() {
        let public_bytes =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let public = PublicKey::from_bytes(&public_bytes).unwrap();
        let bytes = public.as_bytes();
        assert!(bytes == public_bytes[..]);
    }
}
