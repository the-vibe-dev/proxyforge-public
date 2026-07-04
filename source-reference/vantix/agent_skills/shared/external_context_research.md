# External Context Research & Intended-Behavior Gate

Mandatory discipline for the **final-review agents** (`skeptic_validator`,
`referee_arbiter`, `triage_validation`). A working endpoint response is
**not** a finding. Before any candidate may be marked `submit_ready`,
the reviewer must prove the behavior is not documented/expected/standard
/intended, and that a real privilege boundary is crossed.

Driven by the 2026-05-15 platform conduct warning (see operator memory
`feedback_platform_conduct_warning`): a finding parked correctly is a
success; a weak finding submitted under a conduct warning is a failure.
**Be adversarial — try to kill the finding before promoting it.**

## When this runs

On every candidate before `submit_ready`. No exceptions. The skeptic runs
the research pass; the referee re-derives intended-behavior likelihood and
the privilege boundary; triage enforces the promotion gate.

## Mandatory External Research Pass

Local PoC is not enough. Determine whether the behavior is: (1) documented
behavior, (2) expected platform behavior, (3) standard third-party SDK
behavior, (4) required for anonymous/pre-login product flows, (5) already
publicly known, (6) already accepted as normal by the vendor ecosystem,
(7) only impactful under speculative downstream assumptions.

### 1. Vendor documentation
Official docs for the affected vendor/SDK/framework/cloud/API. Answer: is
the token/header/claim/field/response shape normal? is the TTL normal?
is anonymous issuance normal here? is the value meant to be public /
bootstrap-only / client-visible? what controls are normally enforced
downstream?

### 2. Target company documentation
Target help center, developer/support/privacy/security docs, user-facing
instructions. Answer: does the target publicly support this flow? for
unauthenticated users? before login? is it support/onboarding/recovery/
device-setup/public-content? does observed behavior match the documented
user flow?

### 3. Public duplicate & prior-art search
Similar disclosed reports on bug-bounty platforms, public advisories,
source-host issues, blog posts, forum answers, SDK examples/sample
code. Answer: reported before? common false positive? do vendors say
it is safe? known mitigations that make it harmless?

### 4. Real-world mitigation check
Identify mitigations that may make it non-impactful: token generic / not
user-bound; only works inside a server-controlled flow; only one fixed
destination; cannot access account data; needs later server-side
validation; short-lived & scoped; downstream app enforces all authz;
bootstrap (not privileged) token; required for non-member support/recovery.

### 5. Privilege-boundary check
What can anonymous users do before the bug? authenticated users? what NEW
capability does the attacker gain? unauth→auth? user→other-user?
→admin/vendor/internal? **If anonymous and authenticated users receive the
same generic non-user-bound material, treat the finding as likely weak
unless downstream unauthorized capability is proven safely and in scope.**

## Required Promotion Gate

`submit_ready` requires ALL true:
- Clear reproducible steps exist.
- Impact is demonstrated, not merely inferred.
- Public docs do not explain the behavior as intended.
- Standard SDK/vendor behavior does not explain it as normal.
- Target public docs do not support the flow as expected behavior.
- The finding crosses a meaningful privilege boundary.
- Real-world mitigations have been considered.
- No reliance on forbidden testing, DoS, rate limits, speculation, or
  third-party abuse.
- Expected triage outcome is NOT likely Informational / Working as
  Intended / No Security Impact.
- Strong enough to submit under an active platform conduct warning.

Any false → not `submit_ready`.

## Required Parking Rule

If research shows the behavior is probably intended, mark
`parked_do_not_submit`. **Do not dress it up as Medium.** Write a parked
note with: finding title; endpoint/asset; original hypothesis; evidence
collected; public docs reviewed; why behavior is likely intended; what
proof gap remains; what would make it submittable later; final reason for
not submitting.

## Required Output Block (emit per candidate, verbatim schema)

```json
{
  "finding_title": "",
  "asset": "",
  "original_hypothesis": "",
  "local_poc_summary": "",
  "external_research_completed": true,
  "official_vendor_docs_checked": [],
  "target_public_docs_checked": [],
  "public_duplicate_searches": [],
  "standard_behavior_match": "",
  "intended_behavior_likelihood": "low | medium | high",
  "privilege_boundary_crossed": "yes | no | unclear",
  "new_attacker_capability": "",
  "real_world_mitigations": [],
  "proof_gaps": [],
  "safe_to_submit_under_platform_warning": "yes | no",
  "recommended_status": "submit_ready | needs_more_research | parked_do_not_submit",
  "reason": ""
}
```

## Special High-Scrutiny Rule (2026-05-16)

For any finding involving tokens, SDK bootstrap material, support flows,
anonymous app features, pre-login APIs, or vendor-routed features,
increase scrutiny. Explicitly search: "non-member support", "anonymous
support", "pre-login support", "access token TTL", "voice SDK access
token", "application_sid", "identity grant", "bootstrap token",
"anonymous auth", "guest token", "unauthenticated support flow",
"intended behavior". Do not promote unless impact survives that research.

## Worked precedent

Anonymous voice-SDK JWT (2026-05-16): a standard third-party voice-SDK
access token with documented identity + outgoing-call grants and a
vendor-default 1h TTL; `sub`/`iss`/`jti` identical for anonymous vs
authenticated sessions (not user-bound); `identity` ephemeral. The
target publicly supports the anonymous support-call flow.
→ intended-behavior likelihood high, no privilege boundary crossed
→ `parked_do_not_submit`.
