# Private FlakeHub server preview

Last updated: 2026-09-08

Status: current implementation baseline

Owner: CI / Automation

Audience: maintainer using Aegaeon in internal development projects

## Distribution scope

The `FlakeHub Preview` workflow publishes the small `.flakehub/` flake for
authenticated development use. It exposes only `packages.x86_64-linux.server`,
reusing the server derivation from a locked Aegaeon source revision. Its main
executable is `bin/aegaeon-server`. The distribution flake excludes proof/tool
outputs and other platforms from publication inventory evaluation.

A successful consumer job establishes cache retrieval, artifact identity, and
`--help` execution on Linux x86_64. It does not run a login integration test or
activate a server/SDK assurance claim. Release-path qualification and distribution
obligations remain part of the assurance release plan.

`aegaeon-client` is a Rust TLS/HTTP helper library, not an executable SDK. The
TypeScript/WASM SDK belongs to its separate repository and needs its own packaging
change. The [Verified Core handoff](../operations/sdk-release.md) supplies the
WASM input for that work.

## Initial account setup

Use the existing `codetakt/aegaeon` repository identity on FlakeHub. The account
must support private flakes and FlakeHub Cache, with the GitHub repository
connected. Initially grant the maintainer read access. Private visibility applies
to FlakeHub; the existing GitHub repository remains public.

GitHub Actions uses OIDC through `id-token: write`. The workflow installs
Determinate Nix and enables the FlakeHub cache with GitHub artifact-cache fallback
disabled. No personal access token is embedded in the workflow. A separate consumer
job runs after publication and the cache action's upload finalization.

On the consuming workstation, install Determinate Nix and the FlakeHub CLI, then
authenticate with:

```sh
determinate-nixd login
```

For an existing upstream Nix installation, the CLI also supports `fh login` with
a FlakeHub token and the cache configuration it describes. Choose the login
method for the installed Nix distribution; this repository does not replace the
workstation's Nix installation.

Authentication and private-flake access must work for the consuming account. See
[FlakeHub Cache](https://docs.determinate.systems/flakehub/cache/) and
[resolved output paths](https://docs.determinate.systems/flakehub/store-paths/).

## Publish a preview

After the workflow has merged to main and that commit's push workflows have
completed, run:

```sh
gh workflow run flakehub-preview.yml --repo codetakt/aegaeon --ref main
```

The workflow accepts only main in `codetakt/aegaeon`. Before building and again
before publishing, it checks that its publication-recipe revision is still current
main. For both that revision and the server revision locked by `.flakehub/flake.lock`,
the matching **push** run with the greatest run ID must have succeeded for each workflow:
Core, Lint, Security Suite, Formal Verification, Standards Compliance, OIDC KMS
parity, OCI image, and Performance Testing. Scheduled load-test runs and the legacy
F* passthrough are not used as substitutes. Missing, pending, cancelled, or failed
runs stop publication; an earlier successful run does not override a later failure.

The published version has the form `0.1.<commit-count>+rev-<full-commit-sha>` and
identifies the publication recipe's commit. The manifest separately identifies
the locked server source commit. Publishing a new recipe does not silently update
that source. To select a newer main server revision, update the distribution lock,
review its input changes, and merge the update before dispatching:

```sh
nix flake update aegaeon --flake ./.flakehub
```

The publisher registers the server output path with `include-output-paths: true`.
The producer also caches `fh` from the root lockfile's nixpkgs for the consumer.
Both jobs use that Nix package and its runtime closure, rather than assuming a
downloaded CLI executable is portable across Linux installations.

Wait for both **Publish private server preview** and **Fetch the preview on a
fresh runner** to succeed. Publishing alone does not establish a usable preview.
The job summary supplies the exact reference and copyable fetch command.

## Use the built server in another project

Copy the exact reference, including `=`, from the successful run into
`aegaeon-preview.ref` in the consuming project. Commit this version selection if
the project is tracked. Then run from that project:

```sh
AEGAEON_PREVIEW_REF=$(cat aegaeon-preview.ref)
fh fetch "${AEGAEON_PREVIEW_REF}#packages.x86_64-linux.server" ./aegaeon
./aegaeon/bin/aegaeon-server --help
```

`fh fetch` copies the executable and its runtime closure to the Nix store and
creates a GC-root link. It does not compile Aegaeon or install its Rust/F* proof
toolchain. The result is a Nix closure, not a standalone binary that can be copied
to an arbitrary machine. See the [CLI reference](https://docs.determinate.systems/flakehub/cli/).

For a consuming flake, pin the exact published version as an input and commit
`flake.lock`. Use `inputs.aegaeon.packages.${system}.server` directly in the
consumer's shell or service configuration. Preserve the producer's inputs and
features to retain the tested derivation and cache reuse.

Starting a configured server uses the same executable without `--help`.
PostgreSQL, schema migrations, an active management environment/configuration,
issuer selection, and the required Redis endpoints must already be configured.
Follow [runtime configuration operations](../operations/runtime-configuration.md)
and the [environment reference](../configurations/environment/README.md).
The repository's `dev-server` app invokes Cargo and is not the binary-consumption
entrypoint. A self-contained DB/Redis/login example and SDK integration are follow-up
distribution work.

## Evidence and recovery

The publication artifact contains CI run identities for both commits, the Nix
build results, and a manifest with the publication revision, locked server source,
distribution/tooling lockfile digests, exact published reference, executable digest,
and each runtime path's NAR hash. The consumer starts
without the server output, disables local and remote builds, fetches that exact
reference, compares the full closure and executable, and runs `--help`. Its
artifact also contains retrieval and verification logs. These are distribution
records, not an SBOM, independent review, or release-assurance decision.

If main advanced or its CI is incomplete, wait for the new main run and dispatch
again. If private access or cache retrieval fails after publication, correct that
configuration and rerun at the same main revision. The publisher can reuse the
existing rolling release, and the consumer still requires an exact match to the
recorded build. Do not replace the failed retrieval with a local build or change
visibility to make an authentication failure pass.

The workflow is manual and does not publish on PR events. PR validation runs its
gate and manifest regression tests through the Documentation job. The first real
publication, cache access, and fresh-runner retrieval can only be confirmed after
the workflow is on main. Retain the successful run's exact reference and evidence
with the consuming project's experiment record.
