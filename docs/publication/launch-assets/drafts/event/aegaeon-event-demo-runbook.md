# Aegaeon Event Demo Runbook

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This runbook defines how to demonstrate Aegaeon consistently at events.
It is written so booth staff, presenters, and partner staff can all use the same flow.

## Demo goals

- explain Aegaeon in under 2 minutes for casual visitors
- provide a deeper 5-minute path for qualified prospects
- show operational-control value, not only protocol feature lists
- stay inside the released claim boundary

## Demo modes

Prepare two default modes.

### Mode A: 90-second booth demo

Use when:

- the visitor is browsing quickly
- the area is noisy or crowded
- the goal is to qualify whether a follow-up is worth it

### Mode B: 5-minute qualified demo

Use when:

- the visitor is technical
- the visitor has a concrete identity-platform problem
- the conversation can continue without blocking traffic

## Mandatory demo ingredients

Every demo should include:

- what Aegaeon is
- why it exists
- the three pillars
- one concrete control-plane view
- one clear next step

## Demo environment recommendation

- use a stable local or staging environment with fixed sample data
- avoid live environments with changing tenant or audit data
- pre-load the browser tabs needed for the demo
- keep one fallback screenshot deck in case the live demo fails

## Suggested browser tabs

- landing page or overview slide
- architecture diagram
- Admin Console environment or configuration view
- audit / key-management or policy-related screen
- whitepaper / preview request page

## Mode A: 90-second booth demo

### Objective

- help the visitor understand the product and decide whether to continue

### Script

#### Step 1: Opening

Say:

- `Aegaeon は、既存サービスやエンタープライズ基盤に組み込める OAuth/OIDC 基盤です。`

#### Step 2: Why it matters

Say:

- `OAuth/OIDC は実装できても、運用で崩れやすい領域があります。Aegaeon はそこを含めて整備することを重視しています。`

#### Step 3: Three pillars

Point to the visual and say:

- `考え方は3つで、Secure Defaults、Verified Core、Operational Controls です。`

#### Step 4: One concrete screen

Show one Admin Console screen and say:

- `単なる規格対応だけでなく、設定変更や監査、鍵運用まで control-plane として扱えるようにしています。`

#### Step 5: Close

Say:

- `もしご関心があれば、ホワイトペーパーか PoC 相談にすぐつなげられます。`

### Success signal

The visitor asks one of:

- `どこまで対象ですか`
- `何が他と違うのですか`
- `導入するとしたらどう始めますか`

## Mode B: 5-minute qualified demo

### Objective

- move a serious visitor from curiosity to a concrete follow-up

### Script

#### Step 1: Problem statement

Say:

- `認証認可の問題は、実装した時点では終わらず、例外設定、鍵運用、変更管理、監査のところで運用負債が出やすいです。`

#### Step 2: Product definition

Say:

- `Aegaeon は、サーバ側の高保証コア、Secure Defaults、運用統制を一体で整備した OAuth/OIDC 基盤です。`

#### Step 3: Architecture view

Show the architecture diagram and explain:

- data plane
- control plane
- admin console as first-party control-plane UI

Say:

- `主張の中心はサーバ側です。Admin Console は control-plane UI ですが、UI 自体を形式検証済みとは表現していません。`

#### Step 4: Product screen walkthrough

Show a control-plane screen and explain:

- environment or client-management view
- policy or configuration view
- audit or key-management related view

Anchor the explanation in:

- change control
- auditability
- operational repeatability

#### Step 5: Technical credibility route

Only if the visitor asks, show:

- compliance matrix
- assurance-case or assumptions links

Say:

- `現時点の対外表現は、サーバ側の security-critical な OAuth/OIDC コアに関するものです。`

#### Step 6: Close

Ask:

- `評価として資料確認から始めますか、それとも PoC 前提の相談に進めますか。`

## Recommended demo stories by visitor type

### Engineering leader

Emphasize:

- implementation risk reduction
- operational debt reduction
- standardization across teams

### Security architect

Emphasize:

- explicit claim boundary
- secure defaults
- control-plane auditability

### Product / business lead

Emphasize:

- faster adoption of OAuth/OIDC
- reduced long-term operational fragility
- clearer governance story

## Demo do and don't

### Do

- start from the problem, not the acronym list
- show one screen with operational meaning
- repeat the next step clearly
- use the same vocabulary as the LP and handout

### Do not

- start with formal-methods jargon
- over-index on proof details for casual visitors
- imply the UI is formally verified
- imply the first launch includes released SDK / WASM

## Fallback plan if live demo fails

If the live environment is unavailable:

- switch immediately to screenshots or slides
- keep the same story order
- offer to continue the technical walkthrough in a follow-up meeting

## Pre-event demo checklist

- sample environment is populated
- tabs are pre-opened
- screenshots are exported as backup
- QR links are tested
- 90-second and 5-minute talk tracks are rehearsed

## Post-demo CTA mapping

- casual interest -> whitepaper
- evaluation interest -> preview / PoC form
- strong fit -> direct follow-up meeting
