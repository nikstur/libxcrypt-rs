{
  lib,
  rustPlatform,
  libxcrypt,
}:

let
  cargoToml = builtins.fromTOML (builtins.readFile ./xcrypt/Cargo.toml);
in
rustPlatform.buildRustPackage rec {
  pname = "libxcypt-rs";
  inherit (cargoToml.package) version;

  src = lib.sourceFilesBySuffices ./. [
    ".rs"
    ".toml"
    ".lock"
  ];

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [
    rustPlatform.bindgenHook
  ];

  buildInputs = [
    libxcrypt
  ];

  env = {
    LIBXCRYPT_INCLUDE_DIR = "${libxcrypt}/include";
  };

  passthru.envVars = env;

  meta = with lib; {
    homepage = "https://github.com/nikstur/libxcrypt-rs";
    license = licenses.mit;
    maintainers = with lib.maintainers; [ nikstur ];
  };
}
