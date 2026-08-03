# @aegaeon/rp-core

Thin RP orchestration helpers for Authorization Code + PKCE.

Current scope:

- build authorization URLs for `response_type=code`
- normalize issuer metadata and fetch discovery documents
- derive authorization and logout URLs from issuer metadata
- derive `code_challenge` through a Verified Core runtime handle
- capture an authorization transaction snapshot (`state`, `nonce`, `verifier`, `redirectUri`)
- validate callback state and build a token request body from the returned code
- provide in-memory transaction/session stores for RP orchestration
- drive higher-level `startFederatedLogin` / `finishFederatedLogin` flows around callback handling and token exchange callbacks
- build RP-initiated logout request parameters

Non-goals in this alpha package:

- no cryptography reimplementation
- no direct ID Token signature verification logic
- no browser or Node transport layer

Use `@aegaeon/runtime-web` or `@aegaeon/runtime-node` to provide the PKCE runtime handle.
