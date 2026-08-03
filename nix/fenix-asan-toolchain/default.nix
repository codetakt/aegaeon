{
  fenix,
  system,
  patches ? [ ],
}:
let
  channel = fenix.packages.${system}.latest.withComponents [
    "rustc"
    "cargo"
    "rust-std"
    "rust-src"
  ];
in
channel.overrideAttrs (old: {
  patches = (old.patches or [ ]) ++ patches;
})
