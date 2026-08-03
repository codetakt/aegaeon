# Beta Deployment Validation

Last updated: 2026-07-07

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-03-08):** This is a point-in-time deployment validation snapshot. For current release evidence, use `artifacts/release/` and `docs/releases/README.md`.

2025-12-18

## Environment

- Validation date: 2025-12-18
- Raw transcripts for this run are stored under `artifacts/release/beta-deployment/2025-12-18/` (local/CI artefacts; not checked in by default).

## Commands & Evidence

### Nix checks

```bash
nix flake check --print-build-logs
```

- Result: ✅ success (`x86_64-linux`; other systems omitted by default)

### Server build

```bash
nix build .#server -L
```

- Result: ✅ success

### Docker build

```bash
nix run .#docker-build
```

- Result: ✅ success (local image tag: `aegaeon`)

### Docker run (smoke)

```bash
docker run -d --rm --name aegaeon-smoke -p 18080:8080 aegaeon
curl -fsS http://localhost:18080/health
docker logs --tail 200 aegaeon-smoke
docker stop aegaeon-smoke
```

- Result: ✅ `/health` OK

## Notes
- The host-side `8080` port was already in use, so the smoke test used `18080:8080`.
