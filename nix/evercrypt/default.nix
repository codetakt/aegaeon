{
  pkgs ? import <nixpkgs> { },
}:

let
  pinned = pkgs.callPackage ../hacl-star { };
in
{
  source = pkgs.callPackage ./source.nix { inherit (pinned) src version; };
  dist = pkgs.callPackage ./dist.nix { inherit (pinned) src version; };
}
