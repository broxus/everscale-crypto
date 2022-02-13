## everscale-crypto &emsp; [![Latest Version]][crates.io] [![everscale-crypto: rustc 1.56+]][Rust 1.56] [![Workflow badge]][Workflow] [![License MIT badge]][License MIT]

[Latest Version]: https://img.shields.io/crates/v/everscale-crypto.svg
[crates.io]: https://crates.io/crates/everscale-crypto
[everscale-crypto: rustc 1.56+]: https://img.shields.io/badge/rustc-1.56+-lightgray.svg
[Rust 1.56]: https://blog.rust-lang.org/2021/10/21/Rust-1.56.0.html
[Workflow badge]: https://img.shields.io/github/workflow/status/broxus/everscale-crypto/master
[Workflow]: https://github.com/broxus/everscale-crypto/actions?query=workflow%3Amaster
[License MIT badge]: https://img.shields.io/badge/license-MIT-blue.svg
[License MIT]: https://opensource.org/licenses/MIT

Cryptography primitives for Everscale

### Examples

```rust
use everscale_crypto::ed25519;

fn main() {    
    let data: &[u8] = b"hello world";

    let keys = ed25519::KeyPair::generate(&mut rand::thread_rng());
    
    // Simple bytes signature
    let signature = keys.sign_raw(data);
    assert!(keys.public_key.verify_raw(&data, &signature));
    
    // Sign TL data without intermediate serialization
    let signature = keys.sign(keys.public_key.as_tl());
    assert!(keys.public_key.verify(keys.public_key.as_tl(), &signature));

    // Shared secret
    let other_keys = ed25519::KeyPair::generate(&mut rand::thread_rng());
    let secret1 = keys.compute_shared_secret(&other_keys.public_key);
    let secret2 = other_keys.compute_shared_secret(&keys.public_key);
    assert_eq!(secret1, secret2);
}
```
