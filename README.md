# libxcrypt-rs

Rust bindings for [libxcrypt](https://github.com/besser82/libxcrypt)

## Usage

Add `xcrypt` to your `Cargo.toml`:

```sh
cargo add xcrypt
```

Hash a phrase with the best available hashing method and default parameters:

```rust
use xcrypt::{crypt, crypt_gensalt};

fn main() {
    let setting = crypt_gensalt(None, 0, None).unwrap();
    let hashed_phrase = crypt("hello", &setting).unwrap();

    println!("{hashed_phrase}");
}
```
