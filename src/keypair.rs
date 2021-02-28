// Author:
// - Yuzo <yuzonakai@gmail.com>

// Ed25519 interface.

#![allow(non_snake_case)]

use crate::curve25519::group_element::*;

use crate::constants::*;
use crate::errors::*;
use crate::public::*;
use crate::secret::*;
use crate::signature::*;

use sha2::{Digest, Sha512};

// TODO: Tests.
// TODO: Zeroize.

// TODO: configure scalar without precomp as feature?
// TODO: let user choose prng library for generating the secret key.

//? Quite alot of future works and things to explore.

/// A pair of public and secret keys.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    /// Generates asymmetric keys: both public and secret,
    /// as described in RFC 8032.
    /// ! let user choose PRNG here
    pub fn generate() -> Keypair {
        let secret = SecretKey::generate_key();

        // Hash the 32-byte private key using SHA-512, storing the digest in
        // a 64-octet large buffer h. Only the lower 32 bytes are
        // used for generating the public key.
        let h = {
            let mut hash = Sha512::default();
            hash.input(secret.0);
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
        let public = PublicKey(point.encode());

        Keypair { secret, public }
    }

    /// Generates public key by providing your own private key.
    pub fn generate_public_key(sk: SecretKey) -> Keypair {
        let public = PublicKey::generate(&sk);

        Keypair { secret: sk, public }
    }

    /// Converts Keypair to bytes.
    pub fn as_bytes(&self) -> [u8; 64] {
        let mut keypair = [0u8; KeypairSize];
        keypair[..SecretKeySize].copy_from_slice(&self.secret.0);
        keypair[SecretKeySize..].copy_from_slice(&self.public.0);
        keypair
    }

    /// Converts bytes to Keypair.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != KeypairSize {
            return Err(Error::InvalidKeypair);
        }

        let mut secret_bytes: [u8; 32] = [0u8; SecretKeySize];
        secret_bytes.copy_from_slice(&bytes[..SecretKeySize]);
        let mut public_bytes: [u8; 32] = [0u8; PublicKeySize];
        public_bytes.copy_from_slice(&bytes[SecretKeySize..]);

        Ok(Keypair {
            secret: SecretKey(secret_bytes),
            public: PublicKey(public_bytes),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(&self.public, message)
    }

    pub fn verify(&self, message: &[u8], signature: Signature) -> Result<(), Error> {
        self.public.verify(message, &signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::ed25519::*;

    #[test]
    fn as_from_bytes_secret_key() {}
}
