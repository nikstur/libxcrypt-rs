# Changelog

## 0.3.1

### Fixed

- Fixed compilation on targets where `c_ulong` is not represented by `u64`,
  e.g. 32 bit systems.

## 0.3.0

### Fixed

- Fixed compilation on targets where `c_char` is not represented by `i8` but by
  `u8`, e.g. aarch64.

## 0.2.0

### Fixed

- Fixed an issue where we didn't check the return value of `crypt_r` and
  `crypt_gensalt_rn` an only relied on checking `errno`. This led to mistakenly
  returning errors even if the function actually succeeded because something
  else set `errno`.
