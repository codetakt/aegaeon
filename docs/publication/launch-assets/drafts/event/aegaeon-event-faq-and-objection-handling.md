# Aegaeon Event FAQ and Objection Handling

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This sheet is for booth staff, meeting owners, and partner presenters.
It is not public-facing copy. It helps keep answers consistent and within the released claim.

## Usage rule

- answer directly and briefly first
- expand only if the visitor asks for detail
- stay inside the wording guardrails from `docs/product-positioning.md`

## Fast positioning answer

### What is Aegaeon?

Short answer:

- `既存サービスやエンタープライズ基盤に組み込める OAuth/OIDC 基盤です。サーバ側の高保証コア、Secure Defaults、運用統制を一体で整備しています。`

## FAQ

### Q. 何が他の OAuth/OIDC 実装と違うのですか

Short answer:

- `プロトコルの実装だけでなく、運用で壊れやすい部分まで含めて整備している点です。`

Longer answer:

- `Secure Defaults`
- `Verified Core`
- `Operational Controls`

### Q. 形式検証済みということですか

Safe answer:

- `現時点の対外表現は、サーバ側の security-critical な OAuth/OIDC コアに関するものです。`

Do not say:

- `製品全体が形式検証済みです`

### Q. 管理UIも形式検証済みですか

Safe answer:

- `いいえ。Aegaeon Admin Console は first-party control-plane UI ですが、UI 自体を形式検証済みとは表現していません。`

### Q. SDK やクライアントももう出ていますか

Safe answer for first launch:

- `初回公開ではサーバと Admin Console が中心です。SDK / client track は別の公開単位として扱っています。`

### Q. SaaS ですか

Safe answer:

- `初回公開では OSS / Self-hosted の評価導線を中心に案内しています。`

### Q. どんな会社やチームに向いていますか

Safe answer:

- `既存サービスへ認証基盤を組み込みたいチーム、複数サービスの共通認証・API 保護基盤を整備したいチーム、監査や変更管理を厳密にしたい組織に向いています。`

### Q. まず何を見ればよいですか

Safe answer:

- `ホワイトペーパーと Spec Sheet をご覧いただき、必要ならプレビュー版や PoC の相談につなげるのが一番早いです。`

## Objection handling

### Objection 1: 「OAuth/OIDC サーバなら既製品がいろいろありますよね」

Response:

- `その通りです。Aegaeon は単に規格対応をするだけでなく、実装リスクと運用リスクを一緒に下げたいケースに向いています。`

### Objection 2: 「形式検証は現場では過剰ではないですか」

Response:

- `Aegaeon は形式手法だけを売りにしているわけではありません。サーバ側の security-critical なコアに高保証アプローチを使いつつ、日々の運用を支える Secure Defaults と運用統制を組み合わせています。`

### Objection 3: 「結局、運用が難しいのでは」

Response:

- `むしろその逆を狙っています。変更管理、監査、鍵運用、例外設定の扱いを運用の中で壊れにくくすることが Aegaeon の価値です。`

### Objection 4: 「UI まで保証されていないなら弱いのでは」

Response:

- `現在の主張範囲を明確に区切っている点が重要です。サーバ側の高保証主張と、first-party control-plane UI としての Admin Console を混同しない運用を取っています。`

### Objection 5: 「まずは普通の OSS サーバで十分では」

Response:

- `PoC や小規模用途ならそうした判断もあります。ただ、長期運用や監査、鍵運用、例外設定管理まで含めて考える場合には、最初からその前提で設計された基盤の価値が出ます。`

## Escalation path for booth staff

Route the conversation to a deeper owner when:

- the visitor asks about formal proof scope in detail
- the visitor wants to compare architecture with an incumbent platform
- the visitor asks about deployment or PoC planning
- the visitor is a media or partner lead

## Useful closes

- `もし評価を進めるなら、ホワイトペーパーと Spec Sheet を先にご覧いただくのがおすすめです。`
- `具体的な導入前提がおありなら、プレビュー版や PoC の相談をご案内できます。`
- `ブースでは概要中心ですが、必要であれば技術的な背景までご説明します。`
