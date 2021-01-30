// Author:
// - Yuzo <yuzonakai@gmail.com>

// Ed25519 constants.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::field_element::FieldElement;

// Multiple of p: 2 * (2^255 - 19).
pub const TwoP0: u64 = 0x0fffffffffffda;
pub const TwoP1234: u64 = 0x0ffffffffffffe;

// 51-bit mask.
pub const Reduce51Mask: u64 = (1u64 << 51) - 1;

// Ed25519 D constant: -121665/121666 (mod p).
pub const D: FieldElement = FieldElement([
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
]);

// Ed25519 2 * D constant: 2 * (-121665/121666) (mod p).
pub const D2: FieldElement = FieldElement([
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
]);

// Square root of -1 (mod p)
pub const I: FieldElement = FieldElement([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);

pub const FieldZero: FieldElement = FieldElement([0, 0, 0, 0, 0]);

pub const FieldOne: FieldElement = FieldElement([1, 0, 0, 0, 0]);

pub const FieldTwo: FieldElement = FieldElement([2, 0, 0, 0, 0]);

#[cfg(test)]
mod tests {
    #[test]
    fn D() {

    }
}
