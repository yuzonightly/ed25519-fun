// Author:
// - Yuzo <yuzonakai@gmail.com>

extern crate rand;
extern crate sha2;
extern crate subtle;

pub extern crate ed25519 as ed25519_traits;

pub(crate) mod curve25519;

mod constants;
mod errors;
mod keypair;
mod public;
mod secret;
mod signature;

pub use crate::ed25519::*;
pub use crate::keypair::*;
pub use crate::public::*;
pub use crate::secret::*;
pub use crate::signature::*;
pub use ed25519_traits::signature::{Signer, Verifier};
