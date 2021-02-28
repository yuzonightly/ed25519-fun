// Author:
// - Yuzo <yuzonakai@gmail.com>

// Key, signature and verification related errors.

use core::fmt::{self, Display};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// The signature doesn't verify.
    SignatureMismatch,
    /// A weak public key was used.
    WeakPublicKey,
    /// The public key is invalid.
    InvalidPublicKey,
    /// The secret key is invalid.
    InvalidSecretKey,
    /// The signature is invalid.
    InvalidSignature,
    /// The noise doesn't have the expected length.
    InvalidNoise,
    /// The keypair doesn't have the expected length.
    InvalidKeypair,
    /// The signature doesn't have the expected length.
    InvalidSignatureLength,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SignatureMismatch => write!(f, "Signature doesn't verify"),
            Error::WeakPublicKey => write!(f, "Weak public key"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidSecretKey => write!(f, "Invalid secret key"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::InvalidNoise => write!(f, "Invalid noise length"),
            Error::InvalidKeypair => write!(f, "Invalid keypair length"),
            Error::InvalidSignatureLength => write!(f, "Invalid keypair length"),
        }
    }
}
