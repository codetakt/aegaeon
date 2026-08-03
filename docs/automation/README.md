# Automation Overview

Last updated: 2026-07-07

Status: current implementation baseline

Owner: CI / Automation

Audience: CI maintainers, contributors

This directory contains CI/CD and reproducibility guidance for local development,
merge-guard reproduction, and artefact-generation workflows.

## Scope

- GitHub Actions / CI structure
- local reproduction of CI checks via Nix flake entrypoints
- generated-artefact policy and workflow conventions

## Canonical Documents

- `[runbook]` [CI/CD guide](ci-cd-guide.md) — authoritative GitHub Actions / Nix flake / artefact policy reference

## Reading Rule of Thumb

1. Start with `ci-cd-guide.md` for local reproduction of CI.
2. Use `docs/verification/README.md` and `docs/releases/README.md` when you need the downstream evidence locations.
3. Treat GitHub workflow YAML and `flake.nix` as executable counterparts to this documentation.
