{ pkgs }:
# Keep the controller's imports in the pinned interpreter closure. Subject
# dependencies and their Python environments are supplied separately.
pkgs.python3.withPackages (ps: [
  ps.pyyaml
  ps.jsonschema
])
