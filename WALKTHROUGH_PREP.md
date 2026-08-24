# Walkthrough Prep — Likely Questions & Answer Anchors

A companion to `DESIGN_DECISIONS.md` for the live walkthrough. Each question
below has a short **anchor** — not a script to memorize, just the core
reasoning to reach for, with a pointer to the fuller writeup if you want to
say more. Section numbers refer to `DESIGN_DECISIONS.md`.

The best answers here are short and honest, including the ones where the
honest answer is a real limitation. A confident "here's the gap and here's
what I'd do about it" reads better than pretending there isn't one.

## Opening / framing

**"Walk us through your approach."**
Anchor: built in dependency order (network → logging → detection → identity
→ compute → compliance), validated every stack with `cdk synth` before
moving on, documented the reasoning as each decision was made — not
reconstructed afterward. Two decisions worth leading with: the NAT-less
network (§1) and the Config rule set being mapped 1:1 to controls actually
built, not a generic checklist (§7).

**"What's the decision you're most confident about? Least confident about?"**
Anchor: most confident — the NAT-less design; it's a real security *and*
cost win, and it's verified in the synthesized template, not just asserted.
Least confident — it's validated by synthesis, not a live deployment (§10);
I'd want to actually exercise a Session Manager connection before calling it
fully proven.

**"Did you use AI assistance for this?"**
Answer honestly if asked — this is a normal way to build IaC in 2026, and
the interesting question isn't whether you used it, it's whether you
understand what got built. You do: you can explain every control, why it
was chosen over the alternative, and the specific bugs caught along the way
(see "Process" below). That's the actual signal being evaluated.

## Networking (§1)

- **"Why `10.0.0.0/16`?"** — RFC1918 private address space (never routable
  on the public internet, a signal on sight this is internal-only), `/16`
  is a generously sized, standard block — room to grow, no need to redraw
  the map later.
- **"Why 2 AZs and not 3?"** — HA minimum, and the exercise explicitly
  rewards cost-consciousness. Production would likely go to 3.
- **"Why no NAT Gateway? What does the private subnet actually reach?"** —
  Only reachability the instance needs is SSM (3 interface endpoints) and
  S3 (gateway endpoint, patch repos). No NAT means no route to the internet
  at all, not just "no public IP."
- **"What happens if I try to SSH to the instance right now?"** — Times
  out at the network layer. No public IP, no NAT, no inbound security
  group rule, no route from the private subnet to the internet gateway.
  It's not blocked by a firewall rule — there's no path to block.
- **"The NACL allows 443 from anywhere, but the security group is scoped
  to specific ranges — isn't the NACL a downgrade?"** — This is your best
  "I caught a real bug" story. The S3 Gateway Endpoint resolves to real
  AWS-owned IP ranges via a managed prefix list, not VPC-internal
  addresses. This CDK version's NACL construct can't reference a prefix
  list, only raw CIDRs — a VPC-CIDR-only NACL rule would have silently
  broken S3 reachability while everything else kept working. The NACL
  stays a coarse, port-scoped backstop; the security group (which *can*
  reference the actual prefix list) is the real, precise control.
- **"What if the instance needed to reach something outside AWS entirely
  — a third-party API?"** — Deliberate, reviewable addition at that point:
  either a scoped NAT Gateway, or a PrivateLink endpoint if the vendor
  offers one (see §9's CrowdStrike PrivateLink discussion for a concrete
  example of exactly this situation).

## Logging (§2)

- **"Why a customer-managed key instead of S3's default encryption?"** —
  Control over the key policy (exactly who can decrypt), independent
  auditability of key usage, ability to revoke one principal without
  touching a shared default setting.
- **"Why multi-region trail if you're only using one region?"** — Catches
  control-plane activity in regions nobody's actively watching — a common
  blind spot, and cheap insurance against it.
- **"What actually stops someone with admin access from deleting these
  logs?"** — Honestly: within a single account, not much stops a true
  admin — that's inherent to what "admin" means in one account. This is
  exactly why the multi-account design (§8) puts the org trail in a
  separate Log Archive account member accounts can't touch. Good pivot
  point if asked to go deeper.
- **"`auto_delete_objects` on a compliance log bucket — isn't that
  dangerous?"** — Yes, and it's explicitly flagged in the design doc as an
  exercise-only convenience for clean teardown. Would never do this to a
  real log bucket in production.

## Threat Detection & Alerting (§3)

- **"Why 15-minute finding frequency?"** — Fast feedback during testing
  and the walkthrough itself; would tune based on real operational cadence
  and cost in production.
- **"GuardDuty vs. Config — what's the actual difference?"** — GuardDuty:
  active behavioral threat detection ("this looks like an attack in
  progress"). Config: configuration compliance ("this setting drifted
  from what it should be"). Different layers, both needed.
- **"What happens to a MEDIUM-severity GuardDuty finding — does anyone see
  it?"** — Honest gap: only severity ≥7 routes to the alert topic. Lower
  findings sit in GuardDuty's console/API (90-day retention) without a
  push notification. Worth naming as a real threshold decision, not an
  oversight.
- **"Why put GuardDuty findings and break-glass usage in the same
  topic?"** — Both are "needs a human right now." Consolidation over
  silos. At org scale this feeds a ticketing/SOAR system, not just SNS.

## Encryption (§4)

- **"Why separate KMS keys for everything?"** — Scoped access per
  principal population, independent rotation, contained blast radius if
  one key's policy ever needs widening. But be ready to also explain the
  *exceptions* — SNS uses the AWS-managed key, EBS and session logs share
  one key — since defending the exceptions as well as the rule is what
  shows judgment rather than dogma.
- **"What does this actually cost?"** — ~$1/mo per key, prorated to days
  deployed. Small, but worth knowing the number.

## Identity (§5)

- **"Why require MFA in the trust policy instead of an IAM policy
  condition elsewhere?"** — Enforced at the assume-role boundary itself.
  The role *cannot* be assumed without MFA, full stop — not "shouldn't be"
  according to some other policy that could be bypassed or misconfigured.
- **"What happens right now if someone assumes the break-glass role?"** —
  An EventBridge rule matches the `AssumeRole` CloudTrail event for that
  specific role ARN and fires to SNS immediately — not a report someone
  finds later.
- **"Why 1 hour for break-glass vs. 4 hours for auditor?"** — Break-glass
  is emergency-only; short sessions force re-authentication if the
  emergency runs long. Auditor work is often sustained, but still bounded.
- **"Who can actually assume these roles today?"** — Trust policy trusts
  the account root + requires MFA, so any MFA'd principal in this account.
  A deliberate single-account simplification — flag that at multi-account
  scale this becomes real Identity Center permission sets scoped to named
  people (§8).
- **"What stops someone from using break-glass access to grant themselves
  something worse?"** — Honestly, nothing within the account — that's
  inherent to admin access. The alert is a compensating control (fast
  human awareness), not a prevention mechanism. This is exactly the
  detective-vs-preventive distinction §8's SCPs are designed to close.

## Secure Access (§6)

- **"Why not SSH through a bastion host?"** — SSH means a standing open
  port even if IP-restricted; Session Manager means *no* inbound port,
  ever, on this instance or a bastion. No SSH key management/rotation
  either, and every session is centrally logged without needing a
  jump-box to log it separately.
- **"What is IMDSv2 and why require it?"** — Closes the SSRF-to-instance-
  credential-theft path at the platform level — the pattern behind the
  2019 Capital One breach. Cheap to require, easy to forget.
- **"How would you actually know what someone did in a session?"** — The
  Session Manager preferences document streams session I/O to an
  encrypted CloudWatch Logs group in real time.
- **"If the instance role only has SSM permissions, how would you give it
  access to something it needs, like an S3 bucket?"** — Add a narrowly
  scoped statement to the existing role — a deliberate, reviewable
  addition, not a broad grant made up front just in case.

## Configuration Monitoring (§7)

- **"Why Config instead of Security Hub + CIS?"** — A curated set mapped
  1:1 to controls actually built here, vs. ~50 generic checks most of
  which are unrelated to this design. Worth also acknowledging Security
  Hub's real value at multi-account scale for cross-account aggregation
  (§8) — it's not "Config is always better," it's "Config was the better
  fit for this exercise's scope."
- **"When a Config rule finds a violation, does anything happen
  automatically?"** — Honest gap: detective only right now, no
  auto-remediation. Next step would be Config Remediation Configurations
  triggering SSM Automation documents.
- **"Why deliver Config snapshots into the same bucket as CloudTrail?"** —
  Same consumer population (security/compliance review), avoids bucket and
  key sprawl. If pushed on "isn't that a single point of failure" — yes,
  and that's an explicit, named trade-off, not an oversight.

## Cross-cutting trade-offs

- **"Why CDK over Terraform?"** — Matched their stated standardization
  directly; not a personal preference exercise.
- **"If you had one thing to harden further with more time, what would it
  be?"** — Have a real, specific answer ready, not "everything." Strong
  options: Config auto-remediation, or actually validating the NAT-less
  design against a live deployment rather than synthesis alone.
- **"What's the single biggest point of failure in this design?"** — The
  account itself, honestly — a compromised admin credential with
  break-glass access could act before anyone reacts, even with alerting in
  place. Multi-account boundaries (§8) exist specifically to shrink that
  blast radius.

## Failure-mode / "what if"

- **"What if AWS changes the S3 prefix list ID?"** — `PrefixList.from_lookup`
  is a live lookup, not a hardcoded value — a re-synth/redeploy picks up
  the current value automatically.
- **"What if someone deletes the `SSM-SessionManagerRunShell` document?"**
  — Session logging silently stops for *every* session in the account/
  region, not just this instance — it's an account-wide singleton. A real
  operational risk worth naming, and a good candidate for its own Config
  rule if this went further.
- **"What if GuardDuty gets disabled by mistake?"** — Config's
  `GUARDDUTY_ENABLED_CENTRALIZED` rule flags it — but only detects, doesn't
  restore it. Reinforces why §8's SCPs (preventive) matter alongside Config
  (detective).

## Multi-account, CNAPP, and EDR (§8-9) — quick-reference

- Why Control Tower wasn't actually deployed here: it's an org-wide,
  semi-permanent commitment (creates real member accounts) — not something
  to test-drive in a throwaway exercise account.
- The core problem multi-account solves: in one account, the same people
  who operate workloads can also touch the controls meant to catch them —
  unbounded blast radius. Account boundaries are much harder to
  accidentally cross than IAM policy boundaries.
- CNAPP (Wiz/Orca) adds graph-based attack-path analysis — connecting IAM,
  network, and data exposure across resources — which neither GuardDuty
  nor Config do individually.
- The CrowdStrike/NAT-less tension is a good one to bring up unprompted if
  it doesn't come up naturally: a real constraint this design's own
  decisions created, and PrivateLink resolves it without reopening the
  NAT decision.

## Process — be ready to just tell the story

- **"Talk me through a mistake you made and how you caught it."** — You
  have two genuine ones, not hypotheticals: the NACL/S3-prefix-list issue
  (§1), and the ComplianceStack circular dependency from using CDK's
  `.grant_*()` helpers instead of a pseudo-parameter ARN (§7). Both were
  caught by `cdk synth` failing loudly before anything was deployed — a
  good demonstration that the validation step in your workflow actually
  does something, rather than being a formality.
- **"What was the hardest part?"** — Real answer, pick whichever actually
  felt hardest to you when you were in it — the NAT-less design's
  second-order effects (NACL, prefix lists) is a strong, specific choice.

## If it's a manager-track conversation too

- **"How do you explain a technical trade-off to a non-technical
  stakeholder?"** — You just did this exercise — the plain-English
  walkthrough (locked filing cabinets, temporary visitor badges, an
  automatic building inspector) is a real, ready example, not a
  hypothetical.
- **"How do you balance hands-on work with team leadership?"** — Speak
  from your actual 8 years doing both concurrently, not in the abstract.
