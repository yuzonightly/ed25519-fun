// Author:
// - Yuzo <yuzonakai@gmail.com>

// Ed25519 interface.

#![allow(non_snake_case)]

use rand::prelude::ThreadRng;
use rand::thread_rng;
use rand::RngCore;

use crate::constants::*;
use crate::errors::*;
use crate::curve25519::group_element::*;
use crate::curve25519::scalar_ops::*;

use sha2::{Digest, Sha512};

// TODO: configure scalar without precomp as feature.
// TODO: Zeroize.
// TODO: Tests.
// TODO: let user choose prng library for generating the secret key.
// TODO: create curve25519 directory.

// TODO: Quite alot of future works and things to explore.
// TODO: Use this file for ed25519 lib traits.

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

/// A pair of public and secret keys.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

/// The Ed25519 secret key.
#[derive(Copy, Clone)]
pub struct SecretKey(pub(crate) [u8; SecretKeySize]);

/// The Ed25519 public key.
#[derive(Copy, Clone)]
pub struct PublicKey(pub(crate) [u8; PublicKeySize]);

/// The Ed25519 signature.
#[derive(Copy, Clone)]
pub struct Signature(pub(crate) [u8; SignatureSize]);

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

impl PublicKey {
    /// Generates the public key by providing the secret key.
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

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Returns a PublicKey from a slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut public = [0u8; PublicKeySize];

        if bytes.len() != PublicKeySize {
            return Err(Error::InvalidPublicKey);
        }

        public.copy_from_slice(bytes);

        Ok(PublicKey(public))
    }

    /// Verifies the signature.
    pub fn verify(&self, message: &[u8], sig: &Signature) -> Result<(), Error> {
        let signature = sig.as_bytes();
        let s = &signature[32..64];

        if check_lt_l(s) {
            return Err(Error::InvalidSignature);
        }

        // ! Point R from the first half of the signature.

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
        let eq = P2::double_scalar_multiply_vartime(&k[..], &signature[32..64], A);
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

impl Signature {
    pub fn as_bytes(&self) -> [u8; 64] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut signature = [0u8; SignatureSize];

        if bytes.len() != SignatureSize {
            return Err(Error::InvalidSignatureLength);
        }

        signature.copy_from_slice(bytes);
        Ok(Signature(signature))
    }
}

#[cfg(test)]
mod tests {
    use crate::ed25519::*;

    #[test]
    fn as_from_bytes_secret_key() {}
}
