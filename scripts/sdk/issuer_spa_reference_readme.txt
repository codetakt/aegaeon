# @aegaeon/issuer-spa

Alpha browser-facing login orchestration helpers for Aegaeon-compatible issuers.

Current scope:

- initialize the browser runtime through `@aegaeon/runtime-web`
- persist Authorization Code + PKCE transactions
- persist federated session snapshots in memory or browser storage
- fetch issuer discovery metadata and prepare redirect URLs for the login start
- validate callback state and derive token-request bodies
- optionally complete the callback + token exchange through a caller-supplied callback
- build RP-initiated logout URLs directly or from issuer metadata

Non-goals in this alpha package:

- no built-in HTTP token exchange client
- no UI framework bindings
- no cryptography reimplementation

Use `@aegaeon/runtime-web` for runtime initialization and `@aegaeon/rp-core` for lower-level flow helpers.
