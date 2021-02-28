// Author:
// - Yuzo <yuzonakai@gmail.com>

extern crate rand;
extern crate sha2;
extern crate subtle;

pub extern crate ed25519 as ed25519_traits;

pub(crate) mod curve25519;

mod constants;
mod ed25519;
mod errors;

pub use crate::ed25519::*;
pub use ed25519_traits::signature::{Signer, Verifier};
