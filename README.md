# libxcrypt-rs

Rust bindings for libxcrypt

## Usage

Add `xcrypt` to your `Cargo.toml`:

```sh
cargo add xcrypt
```

```rust
use xcrypt::{crypt, crypt_gensalt};

fn main() {
    let setting = crypt_gensalt(None, 0, None).unwrap();
    let hashed_phrase = crypt("hello", &setting);

    println("{hashed_phrase}");
}
```
