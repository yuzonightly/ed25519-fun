// Author:
// - Eduardo Yuzo Nakai <yuzonakai@gmail.com>

// ed25519-rust benchmarks.

extern crate criterion;
extern crate ed25519_rust;

use ed25519::{Keypair, Signature};
use ed25519_rust::ed25519;

use criterion::{criterion_group, criterion_main, Criterion};

fn keypair_generation(c: &mut Criterion) {
    c.bench_function("[Private key + public key] generation.", move |b| {
        b.iter(|| Keypair::generate_keypair())
    });
}

fn signature_generation(c: &mut Criterion) {
    let keypair = Keypair::generate_keypair();
    let message: &[u8] = b"";

    c.bench_function("Signature generation.", move |b| {
        b.iter(|| keypair.sign(message))
    });
}

fn signature_verification(c: &mut Criterion) {
    let keypair = Keypair::generate_keypair();
    let message: &[u8] = b"";
    let signature: Signature = keypair.sign(message);

    c.bench_function("Signature verification.", move |b| {
        b.iter(|| keypair.verify(message, &signature.0))
    });
}

criterion_group! {
    name = ed25519_benchmarks;
    config = Criterion::default();
    targets = keypair_generation,
              signature_generation,
              signature_verification
}

criterion_main!(ed25519_benchmarks);
