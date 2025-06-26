## tycho-crypto &emsp; [![Latest Version]][crates.io] [![tycho-crypto: rustc 1.85+]][Rust 1.85] [![Workflow badge]][Workflow]

[Latest Version]: https://img.shields.io/crates/v/tycho-crypto.svg
[crates.io]: https://crates.io/crates/tycho-crypto
[tycho-crypto: rustc 1.85+]: https://img.shields.io/badge/rustc-1.85+-lightgray.svg
[Rust 1.85]: https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/
[Workflow badge]: https://img.shields.io/github/actions/workflow/status/broxus/tycho-crypto/master.yml?branch=master
[Workflow]: https://github.com/broxus/tycho-crypto/actions?query=workflow%3Amaster

Cryptography primitives for Tycho

### Examples

```rust
use tycho_crypto::ed25519;

fn main() {
    let data: &[u8] = b"hello world";

    let keys = rand::random::<ed25519::KeyPair>();

    // Simple bytes signature
    let signature = keys.sign_raw(data);
    assert!(keys.public_key.verify_raw(&data, &signature));

    // Sign TL data without intermediate serialization
    let signature = keys.sign_tl(keys.public_key.as_tl());
    assert!(keys.public_key.verify_tl(keys.public_key.as_tl(), &signature));

    // Shared secret
    let other_keys = rand::random::<ed25519::KeyPair>();
    let secret1 = keys.compute_shared_secret(&other_keys.public_key);
    let secret2 = other_keys.compute_shared_secret(&keys.public_key);
    assert_eq!(secret1, secret2);
}
```

## Contributing

We welcome contributions to the project! If you notice any issues or errors,
feel free to open an issue or submit a pull request.

## License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)
  or <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT)
  or <https://opensource.org/licenses/MIT>)

at your option.
