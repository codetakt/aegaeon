args@{ profile, ... }:
assert builtins.elem profile [
  "default"
  "strict"
];
(import ./server-test-package.nix (builtins.removeAttrs args [ "profile" ])) {
  inherit profile;
  pname = "aegaeon-jose-server-${profile}-tests";
  dependencyName = "aegaeon-jose-server-${profile}-dependencies";
  command =
    "cargo test --locked -p aegaeon-server --lib --no-run"
    + (if profile == "strict" then " --features verified-claim" else "");
  identityName = "jose-server-build.json";
  buildLog = "jose-build.jsonl";
  installer = "scripts/validation/jose_server_test_package.py";
}
