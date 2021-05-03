// Author:
// - Yuzo <yuzonakai@gmail.com>

// Ed25519 interface.

#![allow(non_snake_case)]

use crate::constants::*;
use crate::errors::*;

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

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::*;

    #[test]
    fn as_from_slices_signature() {
        let sig_bytes = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();
        let sig = Signature::from_bytes(&sig_bytes).unwrap();
        let bytes = sig.as_bytes();
        assert!(bytes == sig_bytes[..]);
    }
}
