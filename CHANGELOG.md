# Changelog

## 0.2.0

### Fixed

- Fixed an issue where we didn't check the return value of `crypt_r` and
  `crypt_gensalt_rn` an only relied on checking `errno`. This led to mistakenly
  returning errors even if the function actually succeeded because something
  else set `errno`.
