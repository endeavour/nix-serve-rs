{
  lib,
  pkg-config,
  rustPlatform,
  sqlite,
}:

rustPlatform.buildRustPackage {
  pname = "nix-serve-rs";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
    ];
  };

  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ sqlite ];

  meta = {
    description = "Async Nix binary cache server";
    mainProgram = "nix-serve-rs";
    license = lib.licenses.lgpl21Plus;
    platforms = lib.platforms.linux;
  };
}
