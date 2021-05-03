# ed25519

Rust implementation of Ed25519. Please do not use it (learning purposes). Heavily based on the `ed25519_donna`, `ed25519_dalek` and str4d's `ed25519-java` implementations. Checkout their implementations instead.

## Installation

I am not going to publish this library on `crates.io`. Therefore, this is one way to import this crate:

- Add the following to your Cargo.toml:

```toml
ed25519-fun = { git = "https://github.com/yuzonightly/ed25519-fun" }
```

## Usage

### Import the crate

```rust
extern crate ed25519_fun;

use ed25519_fun::{Keypair, Signature};
```

### Key generation

Generate a Keypair containing the private and the public key.

```rust
let keypair: Keypair = Keypair::generate();
```

### Signature generation

Generate the signature:

```rust
let message: &[u8] = b"";
let signature: Signature = keypair.sign(message);
```

### Signature verification

Verify the signature:

```rust
let signok: bool = keypair.verify(message, signature);
```

## Benchmarks and Tests

To run the benchmarks, run the following command in the project's root:

```console
me@mars:~/ed25519-fun$ cargo bench
```

To run the tests, run the following command in the project's root:

```console
me@mars:~/ed25519-fun$ cargo test
```
