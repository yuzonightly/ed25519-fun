// Author:
// - Yuzo <yuzonakai@gmail.com>

// This code provides field arithmetic arithmetic modulo p.

use core::ops::Add;
use core::ops::Mul;
use core::ops::Sub;
use std::cmp::{Eq, PartialEq};

use crate::curve25519_const::{Reduce51Mask, TwoP0, TwoP1234};
use crate::utils::{load_8, m6464};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[derive(Copy, Clone)]
pub struct FieldElement(pub [u64; 5]);

impl Eq for FieldElement {}

impl PartialEq for FieldElement {
    fn eq(&self, other: &FieldElement) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl ConstantTimeEq for FieldElement {
    /// Determines if two items are equal in constant time.
    fn ct_eq(&self, other: &FieldElement) -> Choice {
        self.encode().ct_eq(&other.encode())
    }
}

impl Add for FieldElement {
    type Output = FieldElement;

    /// Performs addition of two field elements.
    fn add(self, g: FieldElement) -> FieldElement {
        let mut h = [0u64; 5];

        h[0] = self.0[0] + g.0[0];
        h[1] = self.0[1] + g.0[1];
        h[2] = self.0[2] + g.0[2];
        h[3] = self.0[3] + g.0[3];
        h[4] = self.0[4] + g.0[4];

        FieldElement([h[0], h[1], h[2], h[3], h[4]])
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;

    /// Performs subtraction of two field elements.
    /// Avoids underflow by adding a multiple of P, then
    /// performing the subtraction itself: (self + 2 * P) - g.
    fn sub(self, g: FieldElement) -> FieldElement {
        let mut h = [0u64; 5];

        h[0] = (self.0[0] + TwoP0) - g.0[0];
        h[1] = (self.0[1] + TwoP1234) - g.0[1];
        h[2] = (self.0[2] + TwoP1234) - g.0[2];
        h[3] = (self.0[3] + TwoP1234) - g.0[3];
        h[4] = (self.0[4] + TwoP1234) - g.0[4];

        FieldElement::reduce(h)
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    /// Performs multiplication between two field elements:
    /// self * t.
    fn mul(self, t: FieldElement) -> FieldElement {
        let f: [u64; 5] = self.0;
        let g: [u64; 5] = t.0;

        let g1_19: u64 = 19 * g[1];
        let g2_19: u64 = 19 * g[2];
        let g3_19: u64 = 19 * g[3];
        let g4_19: u64 = 19 * g[4];

        let f0g0: u128 = m6464(f[0], g[0]);
        let f0g1: u128 = m6464(f[0], g[1]);
        let f0g2: u128 = m6464(f[0], g[2]);
        let f0g3: u128 = m6464(f[0], g[3]);
        let f0g4: u128 = m6464(f[0], g[4]);

        let f1g0: u128 = m6464(f[1], g[0]);
        let f1g1: u128 = m6464(f[1], g[1]);
        let f1g2: u128 = m6464(f[1], g[2]);
        let f1g3: u128 = m6464(f[1], g[3]);
        let f1g4_19: u128 = m6464(f[1], g4_19);

        let f2g0: u128 = m6464(f[2], g[0]);
        let f2g1: u128 = m6464(f[2], g[1]);
        let f2g2: u128 = m6464(f[2], g[2]);
        let f2g3_19: u128 = m6464(f[2], g3_19);
        let f2g4_19: u128 = m6464(f[2], g4_19);

        let f3g0: u128 = m6464(f[3], g[0]);
        let f3g1: u128 = m6464(f[3], g[1]);
        let f3g2_19: u128 = m6464(f[3], g2_19);
        let f3g3_19: u128 = m6464(f[3], g3_19);
        let f3g4_19: u128 = m6464(f[3], g4_19);

        let f4g0: u128 = m6464(f[4], g[0]);
        let f4g1_19: u128 = m6464(f[4], g1_19);
        let f4g2_19: u128 = m6464(f[4], g2_19);
        let f4g3_19: u128 = m6464(f[4], g3_19);
        let f4g4_19: u128 = m6464(f[4], g4_19);

        let h0 = f0g0 + f1g4_19 + f2g3_19 + f3g2_19 + f4g1_19;
        let mut h1 = f0g1 + f1g0 + f2g4_19 + f3g3_19 + f4g2_19;
        let mut h2 = f0g2 + f1g1 + f2g0 + f3g4_19 + f4g3_19;
        let mut h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g4_19;
        let mut h4 = f0g4 + f1g3 + f2g2 + f3g1 + f4g0;

        let mut carry: u64;

        let mut r0 = (h0 as u64) & Reduce51Mask;

        carry = (h0 >> 51) as u64;
        h1 += carry as u128;
        let mut r1 = (h1 as u64) & Reduce51Mask;

        carry = (h1 >> 51) as u64;
        h2 += carry as u128;
        let mut r2 = (h2 as u64) & Reduce51Mask;

        carry = (h2 >> 51) as u64;
        h3 += carry as u128;
        let r3 = (h3 as u64) & Reduce51Mask;

        carry = (h3 >> 51) as u64;
        h4 += carry as u128;
        let r4 = (h4 as u64) & Reduce51Mask;

        carry = (h4 >> 51) as u64;
        r0 += carry * 19;

        carry = r0 >> 51;
        r0 &= Reduce51Mask;
        r1 += carry;

        carry = r1 >> 51;
        r1 &= Reduce51Mask;
        r2 += carry;

        FieldElement([r0, r1, r2, r3, r4])
    }
}

impl ConditionallySelectable for FieldElement {
    /// Conditionally select a or b according to choice.
    fn conditional_select(a: &FieldElement, b: &FieldElement, choice: Choice) -> FieldElement {
        let f: [u64; 5] = a.0;
        let g: [u64; 5] = b.0;
        FieldElement([
            u64::conditional_select(&f[0], &g[0], choice),
            u64::conditional_select(&f[1], &g[1], choice),
            u64::conditional_select(&f[2], &g[2], choice),
            u64::conditional_select(&f[3], &g[3], choice),
            u64::conditional_select(&f[4], &g[4], choice),
        ])
    }

    /// Conditionally swap a and b according to choice.
    fn conditional_swap(a: &mut FieldElement, b: &mut FieldElement, choice: Choice) {
        for i in 0..5 {
            u64::conditional_swap(&mut a.0[i], &mut b.0[i], choice);
        }
    }

    /// Conditionally assign b to self according to choice.
    fn conditional_assign(self: &mut Self, b: &FieldElement, choice: Choice) {
        for i in 0..5 {
            self.0[i].conditional_assign(&b.0[i], choice);
        }
    }
}

impl FieldElement {
    /// Determines if the FieldElement is zero.
    pub fn is_zero(&self) -> Choice {
        let zero = [0u8; 32];
        self.encode().ct_eq(&zero).into()
    }

    /// Determines if the FieldElement is negative.
    pub fn is_negative(&self) -> Choice {
        let byte = self.encode()[0];
        (byte & 1).into()
    }

    /// Negates the FieldElement.
    pub fn negate(&self) -> FieldElement {
        let f: [u64; 5] = self.0;

        let out = [
            TwoP0 - f[0],
            TwoP1234 - f[1],
            TwoP1234 - f[2],
            TwoP1234 - f[3],
            TwoP1234 - f[4],
        ];

        FieldElement::reduce(out)
    }

    /// Performs FieldElement reduction.
    pub fn reduce(mut limbs: [u64; 5]) -> FieldElement {
        let mut carry: u64 = limbs[0] >> 51;
        limbs[0] &= Reduce51Mask;

        limbs[1] += carry;
        carry = limbs[1] >> 51;
        limbs[1] &= Reduce51Mask;

        limbs[2] += carry;
        carry = limbs[2] >> 51;
        limbs[2] &= Reduce51Mask;

        limbs[3] += carry;
        carry = limbs[3] >> 51;
        limbs[3] &= Reduce51Mask;

        limbs[4] += carry;
        carry = limbs[4] >> 51;
        limbs[4] &= Reduce51Mask;

        limbs[0] += carry * 19;

        FieldElement(limbs)
    }

    /// h = h[0] + h[1]*2^{51} +...+ h[4]*2^{204}
    /// h = pq + r
    /// r = h - pq
    /// p = 2^255 - 19
    /// Find r = h + q(19 - 2^{255})
    /// Then insert r into a 32-byte array
    pub fn encode(&self) -> [u8; 32] {
        let mut h: [u64; 5] = FieldElement::reduce(self.0).0;

        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;

        h[0] += 19 * q;
        let mut carry: u64;

        // Carry 19*q and discard 2^{255} * q later
        carry = h[0] >> 51;
        h[0] &= Reduce51Mask;
        h[1] += carry;

        carry = h[1] >> 51;
        h[1] &= Reduce51Mask;
        h[2] += carry;

        carry = h[2] >> 51;
        h[2] &= Reduce51Mask;
        h[3] += carry;

        carry = h[3] >> 51;
        h[3] &= Reduce51Mask;
        h[4] += carry;

        // h[4]'s carry is discarded
        // Discarded carry is 2^{255} * q
        // So we have h + q * (19 - 2^{255})
        h[4] &= Reduce51Mask;

        // Insert h into a 32-byte array
        let mut t = [0u8; 32];
        t[0] = h[0] as u8; // [0..7]
        t[1] = (h[0] >> 8) as u8; // [8..15]
        t[2] = (h[0] >> 16) as u8; // [16..23]
        t[3] = (h[0] >> 24) as u8; // [24..31]
        t[4] = (h[0] >> 32) as u8; // [32..39]
        t[5] = (h[0] >> 40) as u8; // [40..47]
        t[6] = (h[0] >> 48 | h[1] << 3) as u8; // [48..50] + [0..4]
        t[7] = (h[1] >> 5) as u8; // [5..12]
        t[8] = (h[1] >> 13) as u8; // [13..20]
        t[9] = (h[1] >> 21) as u8; // [21..28]
        t[10] = (h[1] >> 29) as u8; // [29..36]
        t[11] = (h[1] >> 37) as u8; // [37..44]
        t[12] = (h[1] >> 45 | h[2] << 6) as u8; // [45..50] + [0..1]
        t[13] = (h[2] >> 2) as u8; // [2..9]
        t[14] = (h[2] >> 10) as u8; // [10..17]
        t[15] = (h[2] >> 18) as u8; // [18..25]
        t[16] = (h[2] >> 26) as u8; // [26..33]
        t[17] = (h[2] >> 34) as u8; // [34..41]
        t[18] = (h[2] >> 42) as u8; // [42..49]
        t[19] = (h[2] >> 50 | h[3] << 1) as u8; // [50..50] + [0..6]
        t[20] = (h[3] >> 7) as u8; // [7..14]
        t[21] = (h[3] >> 15) as u8; // [15..22]
        t[22] = (h[3] >> 23) as u8; // [23..30]
        t[23] = (h[3] >> 31) as u8; // [31..38]
        t[24] = (h[3] >> 39) as u8; // [39..46]
        t[25] = (h[3] >> 47 | h[4] << 4) as u8; // [47..50] + [0..3]
        t[26] = (h[4] >> 4) as u8; // [4..11]
        t[27] = (h[4] >> 12) as u8; // [12..19]
        t[28] = (h[4] >> 20) as u8; // [20..27]
        t[29] = (h[4] >> 28) as u8; // [28..35]
        t[30] = (h[4] >> 36) as u8; // [36..43]
        t[31] = (h[4] >> 44) as u8; // [44..51] last bit is zero

        t
    }

    /// Reverts a 32-byte array encoded FieldElement into
    /// a FieldElement.
    pub fn decode(h: [u8; 32]) -> FieldElement {
        let h0: u64 = load_8(&h[0..]) & Reduce51Mask;
        let h1: u64 = load_8(&h[6..]) >> 3 & Reduce51Mask; // shift bit 48 to 51
        let h2: u64 = load_8(&h[12..]) >> 6 & Reduce51Mask; // shift bit 96 to 102
        let h3: u64 = load_8(&h[19..]) >> 1 & Reduce51Mask; // shift bit 152 to 153
        let h4: u64 = load_8(&h[24..]) >> 12 & Reduce51Mask; // shift bit 192 to 204

        FieldElement([h0, h1, h2, h3, h4])
    }

    /// Performs field element squaring:
    /// self^{2 * pow}.
    pub fn square_times(&self, mut pow: u32) -> FieldElement {
        debug_assert!(pow > 0);

        let mut z: [u64; 5] = self.0;

        while pow > 0 {
            let z3_19 = 19 * z[3];
            let z4_19 = 19 * z[4];

            let c0: u128 = m6464(z[0], z[0]) + 2 * (m6464(z[1], z4_19) + m6464(z[2], z3_19));
            let mut c1: u128 = m6464(z[3], z3_19) + 2 * (m6464(z[0], z[1]) + m6464(z[2], z4_19));
            let mut c2: u128 = m6464(z[1], z[1]) + 2 * (m6464(z[0], z[2]) + m6464(z[4], z3_19));
            let mut c3: u128 = m6464(z[4], z4_19) + 2 * (m6464(z[0], z[3]) + m6464(z[1], z[2]));
            let mut c4: u128 = m6464(z[2], z[2]) + 2 * (m6464(z[0], z[4]) + m6464(z[1], z[3]));

            let mut carry: u64;
            let mut r0: u64 = (c0 as u64) & Reduce51Mask;

            carry = (c0 >> 51) as u64;
            c1 += carry as u128;
            let mut r1: u64 = (c1 as u64) & Reduce51Mask;

            carry = (c1 >> 51) as u64;
            c2 += carry as u128;
            let mut r2: u64 = (c2 as u64) & Reduce51Mask;

            carry = (c2 >> 51) as u64;
            c3 += carry as u128;
            let r3: u64 = (c3 as u64) & Reduce51Mask;

            carry = (c3 >> 51) as u64;
            c4 += carry as u128;
            let r4: u64 = (c4 as u64) & Reduce51Mask;

            carry = (c4 >> 51) as u64;
            r0 += carry * 19;
            carry = r0 >> 51;
            r0 &= Reduce51Mask;

            r1 += carry;
            carry = r1 >> 51;
            r1 &= Reduce51Mask;
            // ? This carry is probably not needed
            r2 += carry;

            z[0] = r0;
            z[1] = r1;
            z[2] = r2;
            z[3] = r3;
            z[4] = r4;

            pow -= 1;
        }

        FieldElement(z)
    }

    /// Performs self^2.
    pub fn square(&self) -> FieldElement {
        self.square_times(1)
    }

    /// Performs 2 * self^2.
    pub fn double_square(&self) -> FieldElement {
        let mut double_square = self.square_times(1);
        for i in 0..5 {
            double_square.0[i] *= 2;
        }
        double_square
    }

    /// Performs self^{2^250 - 1}.
    /// Helper function for pow22523() and invert().
    pub fn pow22501(&self) -> (FieldElement, FieldElement) {
        // 1 * 2 = 2
        let mut t0 = self.square();
        // 2 * 2 = 4
        let mut t1 = t0.square();
        // 4 * 2 = 8
        t1 = t1.square();
        // 1 + 8 = 9
        t1 = self.mul(t1);
        // 2 + 9 = 11
        t0 = t0.mul(t1);
        // 2 * 11 = 22
        let mut t2 = t0.square();
        // 22 + 9 = 31
        t1 = t1.mul(t2);
        // 31 * 2 = 62 = 2^6 - 2^1
        t2 = t1.square();
        // 2^4 * (2^6 - 2^1) = 2^10 - 2^5
        t2 = t2.square_times(4);
        // 2^10 - 2^5 + 31 = 2^10 - 2^0
        t1 = t2.mul(t1);
        // 2^11 - 2^1
        t2 = t1.square();
        // 2^20 - 2^10
        t2 = t2.square_times(9);
        // 2^20 - 2^0
        t2 = t2.mul(t1);
        // 2^21 - 2^1
        let mut t3 = t2.square();
        // 2^40 - 2^20
        t3 = t3.square_times(19);
        // 2^40 - 2^0
        t2 = t2.mul(t3);
        // 2^41 - 2^1
        t2 = t2.square();
        // 2^50 - 2^10
        t2 = t2.square_times(9);
        // 2^50 - 2^0
        t1 = t2.mul(t1);
        // 2^51 - 2^1
        t2 = t1.square();
        // 2^100 - 2^50
        t2 = t2.square_times(49);
        // 2^100 - 2^0
        t2 = t2.mul(t1);
        // 2^101 - 2^1
        t3 = t2.square();
        // 2^200 - 2^100
        t3 = t3.square_times(99);
        // 2^200 - 2^0
        t2 = t3.mul(t2);
        // 2^201 - 2^1
        t2 = t2.square();
        // 2^250 - 2^50
        t2 = t2.square_times(49);
        // (11, 2^250 - 2^0)
        (t0, t2.mul(t1))
    }

    /// Performs self^{2^252 - 3}.
    /// Helper function for performing square roots.
    pub fn pow22523(&self) -> FieldElement {
        // 2^250 - 2^0
        let (_, mut a) = self.pow22501();
        // 2^252 - 2^2
        a = a.square().square();
        // 2^252 - 2^2 + 1 = 2^252 - 3
        self.mul(a)
    }

    /// Performs field element inversion:
    /// self^{2^255 - 21} <-> self^{p - 2}.
    pub fn invert(&self) -> FieldElement {
        // a = 11, b = 2^250 - 2^0
        let (a, mut b): (FieldElement, FieldElement) = self.pow22501();
        // 2^255 - 2^5
        for _i in 1..6 {
            b = b.square();
        }
        // 2^255 - 21
        a.mul(b)
    }
}

#[cfg(test)]
mod tests {
    use crate::field_element::FieldElement;
    use subtle::ConditionallySelectable;

    #[test]
    fn conditional_assign_test() {
        let mut f = FieldElement([10, 20, 30, 40, 50]);
        let g = FieldElement([11, 21, 31, 41, 51]);
        let initial_f = f;
        f.conditional_assign(&g, 0.into());
        assert!(f == initial_f);
        f.conditional_assign(&g, 1.into());
        assert!(f == g);
    }

    #[test]
    fn conditional_select_test() {
        let f = FieldElement([10, 20, 30, 40, 50]);
        let g = FieldElement([11, 21, 31, 41, 51]);
        let h1: FieldElement = FieldElement::conditional_select(&f, &g, 0.into());
        assert!(h1 == f);
        let h2: FieldElement = FieldElement::conditional_select(&f, &g, 1.into());
        assert!(h2 == g);
    }

    #[test]
    fn conditional_swap_test() {
        let mut f = FieldElement([10, 20, 30, 40, 50]);
        let mut g = FieldElement([11, 21, 31, 41, 51]);
        let initial_f = f;
        let initial_g = g;
        FieldElement::conditional_swap(&mut f, &mut g, 0.into());
        assert!(f == initial_f && g == initial_g);
        FieldElement::conditional_swap(&mut f, &mut g, 1.into());
        assert!(f == initial_g && g == initial_f);
    }

    #[test]
    fn encoding_test() {
        let f = FieldElement([10, 20, 30, 40, 50]);
        let g = f.encode();
        let h = FieldElement::decode(g);
        assert!(f == h);
    }
}
