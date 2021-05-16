// Author:
// - Yuzo <yuzonakai@gmail.com>

// Utilitarian functions.

/// Input: 64-bit unsigned.
/// Output: 128-bit unsigned.
/// Multiplication between two 64-bit unsigned.
pub fn m6464(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}

/// Test if b and c are equals.
pub fn equal(b: u8, c: u8) -> u8 {
    let mut result: u8 = 0;
    let xor: u8 = b ^ c;
    for i in 0..8 {
        // Make sure the last bit of result is set if
        // b and c are not equal.
        result |= xor >> i;
    }
    (result ^ 0x01) & 0x01
}

/// Converts the first 64 bits from bytes to u64.
pub fn load_8(bytes: &[u8]) -> u64 {
    let h: u64 = (bytes[0] as u64)
        | ((bytes[1] as u64) << 8)
        | ((bytes[2] as u64) << 16)
        | ((bytes[3] as u64) << 24)
        | ((bytes[4] as u64) << 32)
        | ((bytes[5] as u64) << 40)
        | ((bytes[6] as u64) << 48)
        | ((bytes[7] as u64) << 56);

    h
}

/// Converts the first 32 bits from bytes to i64.
pub fn load_4i(bytes: &[u8]) -> i64 {
    let h = (bytes[0] as u64)
        | ((bytes[1] as u64) << 8)
        | ((bytes[2] as u64) << 16)
        | ((bytes[3] as u64) << 24);

    h as i64
}

/// Converts the first 24 bits from bytes to i64.
pub fn load_3i(bytes: &[u8]) -> i64 {
    let h = (bytes[0] as u64) | ((bytes[1] as u64) << 8) | ((bytes[2] as u64) << 16);

    h as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_test() {
        let a = 1;
        let b = 10;
        let c = 1;
        assert!(equal(a, b) == 0u8);
        assert!(equal(a, c) == 1u8);
    }

    #[test]
    fn load_8_test() {
        let a: [u8; 8] = [1, 1, 1, 1, 1, 1, 1, 1];
        let A = 72340172838076673u64;
        let B = load_8(&a);
        assert!(A == B);
    }

    #[test]
    fn load_4i_test() {
        let a: [u8; 4] = [1, 1, 1, 1];
        let A = 16843009i64;
        let B = load_4i(&a);
        assert!(A == B);
    }

    #[test]
    fn load_3i_test() {
        let a: [u8; 3] = [1, 1, 1];
        let A = 65793i64;
        let B = load_3i(&a);
        assert!(A == B);
    }

    #[test]
    fn m6464_test() {
        let a: u64 = 5;
        let b: u64 = 10;
        assert!(50u128 == m6464(a, b));
    }
}
