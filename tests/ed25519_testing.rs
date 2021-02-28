// Author:
// - Eduardo Yuzo Nakai <yuzonakai@gmail.com>

// Regression testing.

extern crate ed25519_fun;
extern crate hex;
extern crate rand;
extern crate sha2;

#[cfg(test)]
mod test_vectors {
    use ed25519_fun::{Keypair, PublicKey, SecretKey, Signature};
    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;

    // http://ed25519.cr.yp.to/python/sign.input
    #[test]
    pub fn ed25519_cr_yp_to_regression_test() {
        let file = File::open("./tests/sign.input");
        if file.is_err() {
            println!("Where are the test vectors? :(");
            panic!();
        }
        let buffer = BufReader::new(file.unwrap());

        // TODO: Move this function to ed25519 interface.
        fn from_bytes(bytes: &[u8]) -> [u8; 32] {
            let mut b_ytes = [0u8; 32];
            b_ytes.copy_from_slice(&bytes[..32]);
            b_ytes
        }
        fn from_sign(bytes: &[u8]) -> [u8; 64] {
            let mut b_ytes = [0u8; 64];
            b_ytes.copy_from_slice(&bytes[..64]);
            b_ytes
        }

        let mut lineno: usize = 0;
        for line in buffer.lines() {
            lineno += 1;

            let l = line.unwrap();
            let slices: Vec<&str> = l.split(":").collect();

            let secret_bytes: Vec<u8> = hex::decode(&slices[0]).unwrap();
            let public_bytes: Vec<u8> = hex::decode(&slices[1]).unwrap();
            let message_bytes: Vec<u8> = hex::decode(&slices[2]).unwrap();
            let signature_bytes: Vec<u8> = hex::decode(&slices[3]).unwrap();

            let secret: SecretKey = SecretKey(from_bytes(&secret_bytes[..32]));

            let pk1: PublicKey = PublicKey(from_bytes(&public_bytes[..32]));
            let sign1: Signature = Signature(from_sign(&signature_bytes[..64]));

            let keypair: Keypair = Keypair::generate_public_key(secret);

            let pk2: PublicKey = keypair.public;
            let sign2: Signature = keypair.sign(&message_bytes);

            assert!(pk1.0 == pk2.0, "Public keys do not match: {}", lineno);
            assert!(sign1.0 == sign2.0, "Signatures do not match: {}", lineno);
            assert!(
                keypair.verify(&message_bytes, &sign1.0),
                "Verification failed: {}",
                lineno
            );
        }
    }
}
