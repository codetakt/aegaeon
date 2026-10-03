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

- `It is an OAuth/OIDC platform that can be embedded in existing services and enterprise infrastructure. It brings together a high-assurance server-side core, Secure Defaults, and operational controls.`

## FAQ

### Q. How does it differ from other OAuth/OIDC implementations?

Short answer:

- `It addresses both protocol implementation and the areas that tend to be fragile in operation.`

Longer answer:

- `Secure Defaults`
- `Verified Core`
- `Operational Controls`

### Q. Does that mean it is formally verified?

Safe answer:

- `Our current public wording concerns the security-critical server-side OAuth/OIDC core.`

Do not say:

- `The entire product is formally verified`

### Q. Is the admin UI also formally verified?

Safe answer:

- `No. Aegaeon Admin Console is a first-party control-plane UI, but we do not describe the UI itself as formally verified.`

### Q. Have the SDK and clients already been released?

Safe answer for first launch:

- `The first release focuses on the server and Admin Console. We treat the SDK / client track as a separate release.`

### Q. Is it SaaS?

Safe answer:

- `For the first release, we focus on evaluation paths for OSS / Self-hosted use.`

### Q. What kinds of companies or teams is it suited to?

Safe answer:

- `It is suited to teams embedding an authentication foundation in existing services, teams establishing shared authentication and API protection across multiple services, and organizations seeking stricter audits and change management.`

### Q. What should I look at first?

Safe answer:

- `The quickest route is to read the whitepaper and Spec Sheet, then discuss a preview or PoC if needed.`

## Objection handling

### Objection 1: "There are already plenty of OAuth/OIDC servers available, aren't there?"

Response:

- `That is true. Aegaeon is suited to cases where you want to reduce both implementation and operational risks, beyond simply supporting the standards.`

### Objection 2: "Isn't formal verification excessive in practice?"

Response:

- `Formal methods are not Aegaeon's only selling point. We use a high-assurance approach for the security-critical server-side core and combine it with Secure Defaults and operational controls that support day-to-day operations.`

### Objection 3: "Won't it still be difficult to operate?"

Response:

- `We aim for the opposite. Aegaeon's value is in making change management, audits, key operations, and exception handling more resilient in operation.`

### Objection 4: "Isn't the assurance weak if it does not cover the UI?"

Response:

- `The key point is that we clearly define the scope of the current claim. We keep the server-side high-assurance claim distinct from Admin Console as a first-party control-plane UI.`

### Objection 5: "Wouldn't an ordinary OSS server be enough to start with?"

Response:

- `That can be a reasonable choice for a PoC or small-scale use. When you also consider long-term operations, audits, key operations, and exception management, a foundation designed for those needs from the start becomes valuable.`

## Escalation path for booth staff

Route the conversation to a deeper owner when:

- the visitor asks about formal proof scope in detail
- the visitor wants to compare architecture with an incumbent platform
- the visitor asks about deployment or PoC planning
- the visitor is a media or partner lead

## Useful closes

- `If you would like to proceed with an evaluation, we recommend starting with the whitepaper and Spec Sheet.`
- `If you have concrete adoption requirements, we can arrange a preview or PoC discussion.`
- `We focus on the overview at the booth, but can explain the technical background if needed.`
