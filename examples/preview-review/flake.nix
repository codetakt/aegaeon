{
  description = "Local review tools for an already built Aegaeon preview";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/ec2d622de0773551768cf98f3fc50cbcc003b9c5";
    server-source = {
      url = "github:codetakt/aegaeon/4f22252f8f0f1320d20c8ce90d6476cc670a3e45";
      flake = false;
    };
  };

  outputs =
    { nixpkgs, server-source, ... }:
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      python = pkgs.python3.withPackages (ps: [
        ps.argon2-cffi
        ps.cryptography
        ps.flask
        ps.psycopg
        ps.pyjwt
        ps.requests
      ]);
    in
    {
      checks.x86_64-linux.review-contract = import ./check.nix { inherit pkgs; };
      devShells.x86_64-linux.default = pkgs.mkShellNoCC {
        packages = [
          python
          pkgs.postgresql_18
          pkgs.redis
          pkgs.atlas
          pkgs.caddy
          pkgs.fh
        ];
        AEGAEON_REVIEW_MIGRATIONS = "${server-source}/db/migrations";
        AEGAEON_REVIEW_SOURCE_REVISION = server-source.rev;
      };
    };
}
