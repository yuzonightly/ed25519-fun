// Author:
// - Yuzo <yuzonakai@gmail.com>

// Ed25519 constants.

#![allow(non_snake_case, non_upper_case_globals)]

// Length of the Ed25519 public key: 32 bytes.
pub(crate) const PublicKeySize: usize = 32;

// Length of the Ed25519 private key: 32 bytes.
pub(crate) const SecretKeySize: usize = 32;

// Length of the Ed25519 signature: 64 bytes.
pub(crate) const SignatureSize: usize = 64;
