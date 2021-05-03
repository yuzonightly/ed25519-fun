// Author:
// - Yuzo <yuzonakai@gmail.com>

// Group element operations.

#![allow(non_snake_case)]

use core::ops::Add;
use core::ops::Sub;
use std::cmp::min;

use super::constants::{FieldOne, FieldZero, D, D2, I};
use super::field_element::FieldElement;
use super::precomp::{BI, PRECOMP_BASE};
use super::utils::equal;

use subtle::{Choice, ConditionallySelectable};

/// Projective representation (P^2): (X : Y : Z), satisfying
/// x = X/Z, y = Y/Z.
#[derive(Clone, Copy)]
pub struct P2 {
    X: FieldElement,
    Y: FieldElement,
    Z: FieldElement,
}

/// Extended representation (P^3): (X : Y : Z : T), satisfying
/// x = X/Z, y = Y/Z, XY = ZT.
#[derive(Clone, Copy)]
pub struct P3 {
    pub X: FieldElement,
    pub Y: FieldElement,
    pub Z: FieldElement,
    pub T: FieldElement,
}

/// Completed representation (P * P): ((X : Z), (Y : T)), satisfying
/// x = X/Z, y = Y/T.
#[derive(Clone, Copy)]
pub struct P1P1 {
    X: FieldElement,
    Y: FieldElement,
    Z: FieldElement,
    T: FieldElement,
}

/// Precomputed representation: (y + x, y - x, 2*D * x*y).
#[derive(Clone, Copy)]
pub struct Precomp {
    pub YpX: FieldElement,
    pub YmX: FieldElement,
    pub XY2d: FieldElement,
}

/// Cached representation: (Y + X, Y - X, Z, 2*D * T).
#[derive(Clone, Copy)]
pub struct Cached {
    YpX: FieldElement,
    YmX: FieldElement,
    Z: FieldElement,
    T2d: FieldElement,
}

impl P1P1 {
    /// Converts P1P1 representation to P2.
    pub fn to_P2(&self) -> P2 {
        let X = self.X * self.T;
        let Y = self.Y * self.Z;
        let Z = self.Z * self.T;

        P2 { X: X, Y: Y, Z: Z }
    }

    /// Converts P1P1 representation to P3.
    pub fn to_P3(&self) -> P3 {
        let X = self.X * self.T;
        let Y = self.Y * self.Z;
        let Z = self.Z * self.T;
        let T = self.X * self.Y;

        P3 {
            X: X,
            Y: Y,
            Z: Z,
            T: T,
        }
    }
}

impl P2 {
    pub fn zero() -> P2 {
        P2 {
            X: FieldZero,
            Y: FieldOne,
            Z: FieldOne,
        }
    }

    /// RFC 8032.
    /// Performs the encoding of the group element.
    pub fn encode(&self) -> [u8; 32] {
        let recip = self.Z.invert(); // recip = Z^-1
        let x = self.X * recip; // recover x = X * recip
        let y = self.Y * recip; // recover y = Y * recip
        let mut s = y.encode();
        s[31] ^= x.is_negative().unwrap_u8() << 7;
        // Sets the most significant bit of the last octet
        // if x is negative.
        // s[31] |= if x.is_negative().unwrap_u8() == 1 {
        //     0x80
        // } else {
        //     0
        // };

        s
    }

    /// Doubles the FieldElement: 2 * self.
    pub fn double(&self) -> P1P1 {
        let xx = self.X.square();
        let yy = self.Y.square();
        let a = self.Z.double_square();
        let YpX = self.X + self.Y;
        let b = YpX.square();

        let y = yy + xx;
        let z = yy - xx;
        let x = b - y;
        let t = a - z;

        P1P1 {
            X: x,
            Y: y,
            Z: z,
            T: t,
        }
    }

    pub fn slide(a: &[u8]) -> [i8; 256] {
        let mut r = [0i8; 256];

        // Each bit in a has its own position in r.
        for i in 0..256 {
            r[i] = (1 & (a[i >> 3] >> (i & 7))) as i8;
        }

        for i in 0..256 {
            if r[i] != 0 {
                for b in 1..min(7, 256 - i) {
                    if r[i + b] != 0 {
                        if r[i] + (r[i + b] << b) <= 15 {
                            r[i] += r[i + b] << b;
                            r[i + b] = 0;
                        } else if r[i] - (r[i + b] << b) >= -15 {
                            r[i] -= r[i + b] << b;
                            for k in i + b..256 {
                                if r[k] == 0 {
                                    r[k] = 1;
                                    break;
                                }
                                r[k] = 0;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        r
    }

    pub fn double_scalar_multiply_vartime(a: &[u8], b: &[u8], A: P3) -> P2 {
        let aslide = P2::slide(a);
        let bslide = P2::slide(b);

        // A * I precomputation.
        // {A, 3A, 5A, 7A, 9A, 11A, 13A, 15A}.
        let mut AI = [Cached {
            YpX: FieldZero,
            YmX: FieldZero,
            Z: FieldZero,
            T2d: FieldZero,
        }; 8];
        AI[0] = A.to_Cached(); // A
        let A2 = A.double().to_P3(); // 2A
        for i in 1..8 {
            // 3A, 5A, 7A, ..., 15A
            AI[i] = (A2.add(AI[i - 1])).to_P3().to_Cached();
        }

        let mut r = P2::zero();
        let mut i: usize = 255;

        loop {
            if aslide[i] != 0 || bslide[i] != 0 {
                break;
            }

            if i == 0 {
                return r;
            }

            i -= 1;
        }

        loop {
            let mut t = r.double();

            if aslide[i] > 0 {
                t = t.to_P3() + AI[(aslide[i] / 2) as usize];
            } else if aslide[i] < 0 {
                t = t.to_P3() - AI[(-aslide[i] / 2) as usize];
            }

            if bslide[i] > 0 {
                t = t.to_P3() + BI[(bslide[i] / 2) as usize];
            } else if bslide[i] < 0 {
                t = t.to_P3() - BI[(-bslide[i] / 2) as usize];
            }

            r = t.to_P2();

            if i == 0 {
                return r;
            }

            i -= 1;
        }
    }
}

impl P3 {
    pub fn zero() -> P3 {
        P3 {
            X: FieldZero,
            Y: FieldOne,
            Z: FieldOne,
            T: FieldZero,
        }
    }

    /// Converts P3 representation to P2.
    pub fn to_P2(&self) -> P2 {
        P2 {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
        }
    }

    /// Converts P3 representation to Cached.
    pub fn to_Cached(&self) -> Cached {
        Cached {
            YpX: self.Y + self.X,
            YmX: self.Y - self.X,
            Z: self.Z,
            T2d: self.T * D2,
        }
    }

    pub fn encode(&self) -> [u8; 32] {
        let recip = self.Z.invert(); // recip = Z^{-1}
        let x = self.X * recip; // recover x = X * recip
        let y = self.Y * recip; // recover y = Y * recip
        let mut s: [u8; 32] = y.encode();
        // s[31] |= if x.is_negative().unwrap_u8() == 1 {
        //     0x80
        // } else {
        //     0
        // };

        s[31] ^= x.is_negative().unwrap_u8() << 7;
        s
    }

    pub fn double(&self) -> P1P1 {
        self.to_P2().double()
    }

    /// Returns a GroupElement given the 32-byte encoded point.
    pub fn decode(enc: [u8; 32]) -> Option<P3> {
        let y = FieldElement::decode(enc);
        let yy = y.square();
        let u = yy - FieldOne;
        let v = (yy * D) + FieldOne;
        let v3 = v.square() * v;
        let v7 = v3.square() * v;
        let mut x = u * v7;
        x = x.pow22523();
        x = x * u * v3;
        let vxx = x.square() * v;
        let mut check = vxx - u;
        if check.is_zero().unwrap_u8() == 0u8 {
            check = vxx + u;
            if check.is_zero().unwrap_u8() == 0u8 {
                return None;
            }
            x = x * I;
        }
        
        if x.is_negative().unwrap_u8() == enc[31] >> 7 {
            x = x.negate();
        }

        Some(P3 {
            X: x,
            Y: y,
            Z: FieldOne,
            T: x * y,
        })
    }
}

impl Precomp {
    pub fn zero() -> Precomp {
        Precomp {
            YpX: FieldOne,
            YmX: FieldOne,
            XY2d: FieldZero,
        }
    }

    /// Assign b to self, according to choice.
    pub fn conditional_assign(&mut self, b: &Precomp, choice: Choice) {
        self.YpX.conditional_assign(&b.YpX, choice);
        self.YmX.conditional_assign(&b.YmX, choice);
        self.XY2d.conditional_assign(&b.XY2d, choice);
    }

    pub fn select(pos: usize, b: i8) -> Precomp {
        // Check if b is negative (1u8: true, 0u8: false)
        let negative = (b as u8) >> 7;

        // If b is negative:
        // we have b - (b << 1), which results in its absolute value.
        // If b is positive:
        // we have b - 0x00 = b.
        let absolute: u8 = (b - (((-(negative as i8)) & b) << 1)) as u8;
        let mut t = Precomp::zero();

        // Assign value based on pos (exponent of base 256) and
        // absolute ([1, 8]).
        // Ex.: if pos = 1 and absolute = 8, t is assigned (8 * 256^{1} * B).
        t.conditional_assign(&PRECOMP_BASE[pos][0], equal(absolute, 1u8).into());
        t.conditional_assign(&PRECOMP_BASE[pos][1], equal(absolute, 2u8).into());
        t.conditional_assign(&PRECOMP_BASE[pos][2], equal(absolute, 3u8).into());
        t.conditional_assign(&PRECOMP_BASE[pos][3], equal(absolute, 4u8).into());
        t.conditional_assign(&PRECOMP_BASE[pos][4], equal(absolute, 5u8).into());
        t.conditional_assign(&PRECOMP_BASE[pos][5], equal(absolute, 6u8).into());
        t.conditional_assign(&PRECOMP_BASE[pos][6], equal(absolute, 7u8).into());
        t.conditional_assign(&PRECOMP_BASE[pos][7], equal(absolute, 8u8).into());

        // Negative of t.
        let negative_t = Precomp {
            YpX: t.YmX,
            YmX: t.YpX,
            XY2d: t.XY2d.negate(),
        };

        // Assign negative of t if b is negative.
        t.conditional_assign(&negative_t, negative.into());

        t
    }

    /// Converts a to radix 16 representation.
    /// a: a[0] + 256 * a[1] + 256^{2} * a[2] + ...
    /// + 256^{31} * a[31].
    fn radix16(a: &[u8]) -> [i8; 64] {
        let mut e = [0i8; 64];

        // Split each byte into two 4-bit values.
        // [e[0]..e[62]] values are between 0 and 15.
        // e[63] is between 0 and 7.
        for i in 0..32 {
            e[2 * i + 0] = (a[i] & 15) as i8;
            e[2 * i + 1] = ((a[i] >> 4) & 15) as i8;
        }

        // Convert each value from e to [-8..7].
        let mut carry: i8 = 0;
        // 10 -> -6, 9 -> -7, 8 -> -8...
        for i in 0..63 {
            e[i] += carry;
            carry = e[i] + 8;
            carry >>= 4;
            e[i] -= carry << 4;
        }
        e[63] += carry;

        e
    }

    /// Performs scalar multiplication h = a * B.
    /// a: a[0] + 256 * a[1] + 256^{2} * a[2] + ...
    /// + 256^{31} * a[31].
    /// B: Ed25519 base point (x, 4/5) with positive x.
    /// Uses precomputed values.
    pub fn scalar_multiply(a: &[u8]) -> P3 {
        let e: [i8; 64] = Precomp::radix16(a);
        let mut t: Precomp;

        let mut h = P3::zero();
        // 64 table lookups
        // 64 point additions
        for i in (1..64).step_by(2) {
            t = Precomp::select(i / 2, e[i]);
            h = (h + t).to_P3();
        }

        // 4 doublings
        h = h
            .double()
            .to_P2()
            .double()
            .to_P2()
            .double()
            .to_P2()
            .double()
            .to_P3();

        // 64 point lookups
        // 64 point additions
        for i in (0..64).step_by(2) {
            t = Precomp::select(i / 2, e[i]);
            h = (h + t).to_P3();
        }

        h
    }

    #[allow(dead_code)]
    pub fn scalar_multiply_without_precomputation(scalar: &[u8]) -> P3 {
        const BXP: [u8; 32] = [
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7,
            0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd,
            0xd3, 0x36, 0x69, 0x21,
        ];
        const BYP: [u8; 32] = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];

        let BX = FieldElement::decode(BXP);
        let BY = FieldElement::decode(BYP);

        let mut q = P3 {
            X: BX,
            Y: BY,
            Z: FieldOne,
            T: BX * BY,
        };

        // p is zero
        let mut p = P3::zero();
        // 256 * 2 point additions
        for i in 0..256 {
            // q to cached (q was B)
            let q_cached = q.to_Cached();
            // add p + q
            let ps = (p + q_cached).to_P3();
            q = (q + q_cached).to_P3();
            let b = ((scalar[(i >> 3)] >> (i as u8 & 7)) & 1) as u8;
            if b == 1u8 {
                p = ps;
            }
        }

        p
    }
}

impl Add<Cached> for P3 {
    type Output = P1P1;

    fn add(self, p: Cached) -> P1P1 {
        let YpX = self.Y + self.X;
        let YmX = self.Y - self.X;
        let a = YpX * p.YpX;
        let b = YmX * p.YmX;
        let c = p.T2d * self.T;
        let d = self.Z * p.Z;
        let e = d + d;

        let x = a - b;
        let y = a + b;
        let z = e + c;
        let t = e - c;

        P1P1 {
            X: x,
            Y: y,
            Z: z,
            T: t,
        }
    }
}

impl Sub<Cached> for P3 {
    type Output = P1P1;

    fn sub(self, p: Cached) -> P1P1 {
        let YpX = self.Y + self.X;
        let YmX = self.Y - self.X;
        let a = YpX * p.YmX;
        let b = YmX * p.YpX;
        let c = p.T2d * self.T;
        let d = self.Z * p.Z;
        let e = d + d;
        let x = a - b;
        let y = a + b;
        let z = e - c;
        let t = e + c;
        P1P1 {
            X: x,
            Y: y,
            Z: z,
            T: t,
        }
    }
}

impl Add<Precomp> for P3 {
    type Output = P1P1;

    fn add(self, p: Precomp) -> P1P1 {
        let YpX = self.Y + self.X; // Y1 + X1
        let YmX = self.Y - self.X; // Y1 - X1
        let a = YpX * p.YpX; // (Y1 + X1) * (Y2 - X2)
        let b = YmX * p.YmX; // (Y1 - X1) * (Y2 - X2)
        let c = p.XY2d * self.T; // D * 2 * (X2 * Y2) * T
        let d = self.Z + self.Z; // Z1 + Z1
        let x = a - b;
        let y = a + b;
        let z = d + c;
        let t = d - c;

        P1P1 {
            X: x,
            Y: y,
            Z: z,
            T: t,
        }
    }
}

impl Sub<Precomp> for P3 {
    type Output = P1P1;

    fn sub(self, p: Precomp) -> P1P1 {
        let YpX = self.Y + self.X; // Y1 + X1
        let YmX = self.Y - self.X; // Y1 - X1
        let a = YpX * p.YmX; // (Y1 + X1) * (Y2 - X2)
        let b = YmX * p.YpX; // (Y1 - X1) * (Y2 - X2)
        let c = p.XY2d * self.T; // 2 * D * (X2 * Y2) * T
        let d = self.Z + self.Z; // Z1 + Z1
        let x = a - b;
        let y = a + b;
        let z = d - c;
        let t = d + c;
        P1P1 {
            X: x,
            Y: y,
            Z: z,
            T: t,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;
    
    use super::*;

    static B_P3: P3 = P3 {
        X: FieldElement([
            1738742601995546,
            1146398526822698,
            2070867633025821,
            562264141797630,
            587772402128613,
        ]),
        Y: FieldElement([
            1801439850948184,
            1351079888211148,
            450359962737049,
            900719925474099,
            1801439850948198,
        ]),
        Z: FieldElement([1, 0, 0, 0, 0]),
        T: FieldElement([
            1841354044333475,
            16398895984059,
            755974180946558,
            900171276175154,
            1821297809914039,
        ]),
    };
    

    static BYP: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66,
    ];

    #[test]
    fn encoding_test() {
        // let a = hex::decode("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c").unwrap();
        // let mut a_bytes = [0u8; 32];
        // a_bytes.copy_from_slice(&a);
        let mut BY = BYP.clone();
        // BY[31] |= 1 << 7;
        let B = P3::decode(BY).unwrap();

        assert!(B.X == B_P3.X.negate());
        assert!(B.Y == B_P3.Y);
        assert!(B.Z == B_P3.Z);
        assert!(B.T == B_P3.T.negate());
        
        let b = B.encode();
        BY[31] |= 1 << 7;
        assert!(b == BY);
    }

    #[test]
    fn scalar_multiply_test() {
        let a = hex::decode("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c").unwrap();
        let aB = Precomp::scalar_multiply(&a);

        let A = hex::decode("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66").unwrap();
        // let mut A_bytes = [0u8; 32];
        // A_bytes.copy_from_slice(&A);
        // let AB = P3::decode(A_bytes).unwrap();

        assert!(aB.encode() == A[..]);
        
        // assert!(aB.X == AB.X);
        // assert!(aB.Y == AB.Y);
        // assert!(aB.Z == AB.Z);
        // assert!(aB.T == AB.T);
    }

    #[test]
    fn scalar_multiply_no_precomp_test() {
        let a = hex::decode("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c").unwrap();
        let aB = Precomp::scalar_multiply_without_precomputation(&a);

        let A = hex::decode("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66").unwrap();
        // let mut A_bytes = [0u8; 32];
        // A_bytes.copy_from_slice(&A);
        // let AB = P3::decode(A_bytes).unwrap();

        assert!(aB.encode() == A[..]);

        // assert!(aB.X == AB.X);
        // assert!(aB.Y == AB.Y);
        // assert!(aB.Z == AB.Z);
        // assert!(aB.T == AB.T);
    }

    #[test]
    fn double_scalar_multiply_vartime_and_point_doubling_test() {
        let a = hex::decode("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c").unwrap();
        let two = hex::decode("0200000000000000000000000000000000000000000000000000000000000000").unwrap();

        // let A_bytes = hex::decode("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66").unwrap();
        // let mut A_array = [0u8; 32];
        // A_array.copy_from_slice(&A_bytes);
        // let A = P3::decode(A_array).unwrap();

        let B = B_P3.clone();
        let four_B = P2::double_scalar_multiply_vartime(&two, &two, B).encode();
        let B_four = B.double().to_P3().double().to_P2().encode();

        assert!(four_B == B_four);
    }
}
