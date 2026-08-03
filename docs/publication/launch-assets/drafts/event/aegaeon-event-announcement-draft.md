# Aegaeon Event Announcement Draft

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This is a reusable event-announcement draft for any 2026 event where Aegaeon will appear.
Replace the placeholders with the actual event name, date, venue, and meeting URL.

## Usage

Use this draft for:

- website news post
- LinkedIn / X announcement
- partner announcement adaptation
- email invitation to existing contacts

## Event metadata placeholders

- Event name: `[event name]`
- Dates: `[event dates]`
- Venue: `[venue]`
- Booth / area: `[booth number or area]`
- Meeting link: `[meeting booking URL]`

## Website / newsroom version

### Title

Aegaeon、[event name] に出展

### Subtitle

高保証コア、Secure Defaults、運用統制を備えた OAuth/OIDC 基盤を紹介

### Lead

Aegaeon は、[event dates] に [venue] で開催される [event name] に出展します。
当日は、既存サービスやエンタープライズ基盤に組み込める OAuth/OIDC 基盤としての
Aegaeon を紹介し、サーバ側の高保証コア、Secure Defaults、運用統制を中心に
デモと個別相談を実施します。

### Body

Aegaeon は、認証認可の課題をプロトコル実装だけでなく、運用まで含めて捉えることを
重視しています。会場では、以下のポイントを中心に紹介します。

- Secure Defaults:
  危険な構成を避けやすい既定値と、例外設定を統制下で扱う考え方
- Verified Core:
  PKCE、DPoP、JOSE など、サーバ側の security-critical な OAuth/OIDC コアへの
  高保証アプローチ
- Operational Controls:
  Aegaeon Admin Console を通じた変更管理、監査、鍵運用、RBAC の考え方

また、Aegaeon を既存プロダクトに組み込むケースや、共通認証・API 保護基盤として
利用するケースを想定した相談も受け付けます。

### At-the-event CTA

- デモをご覧になりたい方は、ブースでスタッフにお声がけください
- 個別相談をご希望の方は、事前または当日にミーティングをご予約ください
- ホワイトペーパーと Spec Sheet は会場からも参照できます

### Closing block

[event name] で Aegaeon に関心をお持ちの方は、ぜひブースにお立ち寄りください。
評価・PoC・協業に関するご相談を受け付けています。

## Short site version

### Heading

[event name] に出展します

### Body

Aegaeon は [event name] に出展し、高保証コア、Secure Defaults、運用統制を備えた
OAuth/OIDC 基盤としての取り組みを紹介します。ブースではデモと個別相談を実施します。

### CTA

ミーティングを予約する

## Social post drafts

### LinkedIn

Aegaeon は [event name] に出展します。

既存サービスやエンタープライズ基盤に組み込める OAuth/OIDC 基盤として、
サーバ側の高保証コア、Secure Defaults、運用統制を中心にご紹介します。

会場ではデモと個別相談を実施予定です。
[meeting link]

### X / short post

Aegaeon は [event name] に出展します。
高保証コア、Secure Defaults、運用統制を備えた OAuth/OIDC 基盤をご紹介します。
デモ / 個別相談はこちら: [meeting link]

## Event page content blocks

If the event needs its own site section, use these blocks:

- what Aegaeon is
- what will be shown at the booth
- who should talk to us
- meeting booking CTA
- whitepaper / Spec Sheet links

## Copy guardrails

- keep `Verified Core` anchored to the server side
- describe the admin console as a first-party control-plane UI
- do not present the event as an SDK launch unless that release is already public
- do not let event hype widen the claim boundary
