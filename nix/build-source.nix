# Production compilation excludes prose; tests and verification retain full source.
{ lib, source }:
lib.cleanSourceWith {
  src = source;
  name = "aegaeon-build-source";
  filter =
    path: _type:
    let
      root = source.origSrc or source;
      relative = lib.removePrefix "${toString root}/" (toString path);
      rootMarkdown = !(lib.hasInfix "/" relative) && lib.hasSuffix ".md" relative;
    in
    relative != "docs" && !(lib.hasPrefix "docs/" relative) && !rootMarkdown;
}
