// Author:
// - Yuzo <yuzonakai@gmail.com>

// Ed25519 interface.

#![allow(non_snake_case)]

use rand::prelude::ThreadRng;
use rand::thread_rng;
use rand::RngCore;

use crate::curve25519::group_element::*;
use crate::curve25519::scalar_ops::*;

use crate::constants::*;
use crate::errors::*;
use crate::public::*;
use crate::signature::*;

use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// The Ed25519 secret key.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub(crate) [u8; SecretKeySize]);

impl SecretKey {
    /// Generates the secret key: 32 octets of cryptographically
    /// secure random data.
    pub(crate) fn generate_key() -> SecretKey {
        let mut sk = [0u8; 32];
        let mut csprng: ThreadRng = thread_rng();
        csprng.fill_bytes(&mut sk);
        SecretKey(sk)
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Returns a SecretKey from a slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut secret = [0u8; SecretKeySize];
        if bytes.len() != SecretKeySize {
            return Err(Error::InvalidSecretKey);
        }
        secret.copy_from_slice(bytes);
        Ok(SecretKey(secret))
    }

    /// RFC 8032.
    /// Generates the signature.
    pub fn sign(&self, public: &PublicKey, message: &[u8]) -> Signature {
        // Hash the secret key using SHA-512.
        let h = {
            let mut hash = Sha512::new();
            hash.input(self.0);
            let mut output = hash.result();
            output[0] &= 248;
            output[31] &= 63;
            output[31] |= 64;
            output
        };

        // Compute SHA-512(prefix || PH(M)), where M is the
        // message to be signed and prefix is the second half of h.
        // Interpret the 64-octet digest as a little-endian integer r.
        let mut r = {
            let mut hash = Sha512::default();
            hash.input(&h[32..64]);
            hash.input(message);
            hash.result()
        };

        // Compute the point [r]B.  For efficiency, do this by first
        // reducing r modulo L, the group order of B.
        reduce(&mut r[..]);
        let R: P3 = Precomp::scalar_multiply(&r[0..32]);

        // Compute SHA512(enc(R) || A || PH(M)), and interpret the
        // 64-octet digest as a little-endian integer k.
        let mut k = {
            let mut hash = Sha512::default();
            hash.input(&R.encode());
            hash.input(public.0);
            hash.input(&message);
            hash.result()
        };
        reduce(&mut k[..]);

        // The signature.
        let mut signature = [0u8; 64];
        // Populate the second half of the signature with the
        // result of (r + k * s) mod L.
        multiply_add(&mut signature[32..64], &k[0..32], &h[0..32], &r);

        // Populate the first half of the signature with the
        // encoding of R.
        for (result_byte, source_byte) in &mut signature[0..32].iter_mut().zip(R.encode().iter()) {
            *result_byte = *source_byte;
        }

        Signature(signature)
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::*;

    #[test]
    fn as_from_slices_secret_key() {
        let secret_bytes =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let secret = SecretKey::from_bytes(&secret_bytes).unwrap();
        let bytes = secret.as_bytes();
        assert!(bytes == secret_bytes[..]);
    }
}
