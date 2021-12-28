// Author:
// - Yuzo <yuzonakai@gmail.com>

// Ed25519 interface.

#![allow(non_snake_case)]

use crate::constants::*;
use crate::errors::*;
use crate::public::*;
use crate::secret::*;
use crate::signature::*;

/// A pair of public and secret keys.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    /// Generates asymmetric keys: secret and public keys;
    /// as described in RFC 8032.
    ///
    /// Returns `Keypair` containing the secret and public keys.
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate ed25519_fun;
    ///
    /// use ed25519_fun::{Keypair};
    ///
    /// fn main() {
    ///     let keypair = Keypair::generate();
    /// }
    /// ```
    pub fn generate() -> Keypair {
        let secret = SecretKey::generate_key();
        let public = PublicKey::generate(&secret);
        Keypair { secret, public }
    }

    /// Generates `Keypair` by providing a `SecretKey`.
    ///
    /// Returns a `Keypair` containing `SecretKey` and `PublicKey`.
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate ed25519_fun;
    ///
    /// use ed25519_fun::{Keypair, SecretKey};
    ///
    /// fn main() {
    ///     let keypair = Keypair::generate();
    ///     let secret_key: SecretKey = keypair.secret;
    ///     let keypair_from_secret_key: Keypair = Keypair::generate_public_key(secret_key);
    /// }
    /// ```
    pub fn generate_public_key(secret: SecretKey) -> Keypair {
        let public = PublicKey::generate(&secret);

        Keypair { secret, public }
    }

    /// Converts `Keypair` into a 64-byte array.
    ///
    /// Returns a 64-byte array `[u8; 64]`.
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate ed25519_fun;
    ///
    /// use ed25519_fun::{Keypair};
    ///
    /// fn main() {
    ///     let keypair = Keypair::generate();
    ///     let bytes: [u8; 64] = keypair.as_bytes();
    /// }
    /// ```
    pub fn as_bytes(&self) -> [u8; 64] {
        let mut keypair = [0u8; KeypairSize];
        keypair[..SecretKeySize].copy_from_slice(&self.secret.0);
        keypair[SecretKeySize..].copy_from_slice(&self.public.0);
        keypair
    }

    /// Constructs `Keypair` from a slice.
    ///
    /// Returns `Ok(Keypair)` if `bytes` is 64 bytes long and `Err` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate ed25519_fun;
    ///
    /// use ed25519_fun::{Keypair};
    ///
    /// fn main() {
    ///     let keypair = Keypair::generate();
    ///     let bytes: [u8; 64] = keypair.as_bytes();
    ///     let keypair_from_bytes: Keypair = Keypair::from_bytes(&bytes).unwrap();
    /// }
    /// ```
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

    /// Signs a message with this `Keypair`.
    ///
    /// Returns `Signature`.
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
    ///     let signature: Signature = keypair.sign(message);
    /// }
    /// ```
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(&self.public, message)
    }

    /// Verifies a signature with this `Keypair`.
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
    ///     let signature: Signature = keypair.sign(message);
    ///     let _signok = keypair.verify(message, signature).unwrap();
    /// }
    /// ```
    pub fn verify(&self, message: &[u8], signature: Signature) -> Result<(), Error> {
        self.public.verify(message, &signature)
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::*;

    #[test]
    fn as_from_slices_keypair() {
        let keypair_bytes = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        let keypair = Keypair::from_bytes(&keypair_bytes).unwrap();
        let bytes = keypair.as_bytes();
        assert!(bytes == keypair_bytes[..]);
    }
}
