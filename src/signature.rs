// Author:
// - Yuzo <yuzonakai@gmail.com>

// Ed25519 interface.

#![allow(non_snake_case)]

use crate::constants::*;
use crate::errors::*;

// TODO: configure scalar without precomp as feature.
// TODO: Zeroize.
// TODO: Tests.
// TODO: let user choose prng library for generating the secret key.
// TODO: create curve25519 directory.

// ? I believe I should comment all functions like this one SergioBenitez/stable-pattern ehehh
// TODO: Quite alot of future works and things to explore.
// TODO: Use this file for ed25519 lib traits.

/// The Ed25519 signature.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Signature(pub(crate) [u8; SignatureSize]);

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
