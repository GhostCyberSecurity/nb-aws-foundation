# Design Decisions — Secure AWS Foundation

This document captures the key architectural and security decisions made in this
exercise, and the reasoning behind each. Sections are added as each component is
built.

**tl;dr for the walkthrough:** every required control is implemented (§1-7). The
two decisions most worth leading with: (1) the private subnet has *zero* route to
the internet — no NAT Gateway at all, reachability is entirely through VPC
endpoints — which is a stronger posture than the typical "private + NAT" pattern
and cheaper; (2) the Config rule set (§7) isn't a generic best-practices
checklist, it's one rule per control actually built here, so it doubles as a
drift detector for this specific design. §8 covers the multi-account evolution
this single-account exercise deliberately doesn't build. §9 covers where a CNAPP
(Wiz/Orca) and CrowdStrike Falcon fit — including a real tension worth raising
unprompted: Falcon needs internet egress, this design has none, and PrivateLink
resolves it without compromising the NAT-less decision. §10 is a direct list of
what's out of scope and why.

## 0. Foundational Assumptions

| Decision | Rationale |
|---|---|
| **Single AWS account** for this exercise | The exercise provides one temporary account. All controls (IAM boundaries, SCP-equivalents, logging) are scoped accordingly. Section 8 (multi-account strategy) covers how this decomposes into an Organizations/Control Tower model for production. |
| **Single region deployment**, multi-AZ within it | Multi-region adds real cost/complexity (cross-region replication, latency) that isn't justified for a scoped exercise. CloudTrail is still configured as multi-region trail (requirement #2) because trail *coverage* should be multi-region even when workloads aren't — this catches control-plane activity in any region, including ones we don't actively use, which is a common blind spot. |
| **2 Availability Zones**, not 3 | Balances the "multi-AZ" requirement against cost-consciousness (the notes explicitly reward this). 2 AZs is the practical minimum for HA; I'll call out in the design doc that production would likely go to 3 AZs for a regulated workload. |
| **IaC tool: AWS CDK (Python)** | Matches their stated standardization. Also lets me express security intent (e.g., "this bucket is not public") as first-class, typed constructs rather than hoping HCL/YAML boilerplate is right — CDK's L2 constructs default-deny a lot of the things that create classic S3/IAM misconfigurations. |
| **Everything in one CDK App, multiple Stacks** | Stacks: `NetworkingStack`, `LoggingStack`, `SecurityStack` (GuardDuty, Config/Security Hub), `IdentityStack`, `ComputeStack`. Mirrors how you'd actually split these in a larger org (separable ownership, blast radius, deploy cadence) even though one team owns all of it here. |

## 1. Networking (`NetworkingStack`)

| Decision | Rationale |
|---|---|
| VPC `10.0.0.0/16`, 2 AZs, one public `/24` + one private `/24` per AZ | Standard, non-overlapping RFC1918 space; room to grow without needing to be large for a 1-instance exercise. |
| Private subnet type is `PRIVATE_ISOLATED`, not `PRIVATE_WITH_EGRESS` — **no NAT Gateway at all** | The only workload in this subnet is the SSM-managed EC2 instance (req #5). It doesn't need general internet egress. Reachability to AWS services is via VPC endpoints instead of NAT, which removes an entire class of "compromised instance calls out to the internet" risk and saves ~$32-65/mo + data processing versus one NAT GW per AZ. If a future workload needs real internet egress, that's a deliberate, reviewable addition — not a default. |
| S3 Gateway Endpoint + Interface Endpoints for SSM, SSMMessages, EC2Messages, all restricted to the private subnets | This is what makes the NAT-less design work: Session Manager and Amazon Linux patch repos (S3-hosted) both stay on AWS's private network path (PrivateLink), never traversing the public internet. |
| Interface endpoints share one SG that allows inbound 443 **from the VPC CIDR only** | Endpoints are the only thing in this VPC that should ever receive inbound connections; scoping to the VPC CIDR (rather than 0.0.0.0/0 with SG defaults) means nothing outside the VPC can ever reach them, even if someone later attaches a public IP to something. |
| Custom NACLs, default-deny, allow 443/ephemeral for HTTPS on the private subnet | NACLs are stateless and secondary to SGs (defense-in-depth, not the primary control). **Correction made during the build:** the private-subnet NACL is scoped to `0.0.0.0/0` on 443, not the VPC CIDR — traffic to the S3 Gateway Endpoint resolves to real AWS-owned S3 IP ranges via a managed prefix list, not VPC-internal addresses, and this CDK version's `NetworkAcl` can't reference a prefix list (CIDR only). A VPC-CIDR-only rule would have silently broken S3 reachability (patch repos, SSM agent dependencies) while SSM-endpoint traffic kept working fine — exactly the kind of partial failure that's miserable to debug after the fact. The NACL stays protocol/port-scoped (443 only, nothing else); the **security group** is where the precise VPC-CIDR + S3-prefix-list restriction actually lives, since SGs do support prefix-list references. |
| VPC Flow Logs → CloudWatch Logs, encrypted with a dedicated CMK, 1-month retention | Network-level visibility from day one, independent of CloudTrail (which covers API/control-plane activity, not packet flow). Its own CMK (rather than sharing CloudTrail's) keeps key policies scoped to exactly the principals that need flow-log access. |

## 2. Logging (`LoggingStack`)

| Decision | Rationale |
|---|---|
| Dedicated CMK for CloudTrail, separate from the flow-log CMK | Same reasoning as above — scoped key policies, independent rotation, and if this key's policy ever needs to be widened (e.g., to let a SIEM read encrypted trail objects), that grant doesn't also touch flow-log data. |
| Key policy explicitly scopes `kms:GenerateDataKey*` to `cloudtrail.amazonaws.com` with an `EncryptionContext` condition tied to trail ARNs, plus a separate narrow `kms:DescribeKey` statement | CDK's `Trail` construct will wire up what it needs automatically, but I added explicit statements so the *intent* is auditable directly in the key policy — a reviewer shouldn't have to trust that CDK "did the right thing"; they should be able to read the policy and see exactly which service, and under what condition, can use the key. |
| S3 bucket: `BLOCK_ALL` public access, `BUCKET_OWNER_ENFORCED` ownership (disables ACLs entirely), versioned, KMS-encrypted with bucket keys enabled, `enforce_ssl=True` | Each setting closes a specific historical CloudTrail-bucket misconfiguration: `BLOCK_ALL` prevents accidental public exposure regardless of any bucket/object ACL; disabling ACLs outright (bucket-owner-enforced) removes an entire class of "someone granted the wrong grantee" mistakes; versioning + a restrictive bucket policy means even a compromised principal with `PutObject` can't overwrite history, only add to it; `enforce_ssl` adds an explicit bucket-policy deny on non-TLS requests, not just "encryption at rest." |
| Bucket policy grants CloudTrail `s3:GetBucketAcl` and a conditioned `s3:PutObject` (requires `bucket-owner-full-control`), and nothing else to any other principal | This is the minimum CloudTrail needs to deliver logs — no read access for CloudTrail itself, no delete, no broader `s3:*`. Anyone who *does* need to read the logs (security team, SIEM ingestion role) gets a separate, explicitly-added statement — not implied by "it's the log bucket." |
| Trail is multi-region, includes global service events, has file validation (digest files) enabled, and also streams to CloudWatch Logs | Multi-region + global events = no blind spot in a region we're not actively using. File validation gives tamper-evidence (a required control in most compliance frameworks, incl. what a bank's auditors will expect). CloudWatch Logs gives near-real-time searchability/alerting — S3 alone means "durable but not queryable without Athena." |
| `auto_delete_objects=True` on the bucket (via CDK's custom resource) | Directly supports the exercise's "destroy or leave clean" requirement — `cdk destroy` actually empties and removes the bucket instead of failing or leaving an orphaned bucket behind. **This would be removed for a production/regulated deployment** — you do not want log data auto-deletable by an IaC destroy in a real environment; retention there should be governed by a records-retention policy, not a stack lifecycle. Flagging this explicitly so it's clear it's an exercise-only convenience. |

## 3. Threat Detection (`SecurityStack`) + shared alerting

| Decision | Rationale |
|---|---|
| GuardDuty enabled, 15-minute finding publishing frequency | Fastest available option, so findings show up quickly during testing and the live walkthrough rather than sitting in a 6-hour default window. |
| `S3_DATA_EVENTS` and `EBS_MALWARE_PROTECTION` features enabled; no S3 export destination for findings | Malware Protection is relevant since we do have an EC2 instance. Findings retain 90 days natively in GuardDuty, which outlives this exercise — exporting to S3/Security Lake for long-term retention/SIEM ingestion is the right production move but isn't justified for a temporary account; called out as a forward-looking item rather than built. |
| One shared SNS topic (`SecurityAlertsTopic`) for both GuardDuty HIGH-severity findings (severity ≥ 7) and break-glass role-assumption alerts | "Things a human needs to see right now" belongs in one place, not scattered per-stack. This is also the seed of a real detection/alerting pipeline — next step in a production build would be routing this into a ticketing system or paging tool instead of (or in addition to) email/SMS subscribers. |
| SNS topic uses the AWS-managed key, not a dedicated CMK | The payload is finding IDs/summaries and role-assumption metadata — not the underlying sensitive data. A dedicated CMK's key-policy overhead isn't earning its keep here; worth revisiting if this topic's payloads change. |

## 4. Encryption

Requirement #4 ("customer-managed KMS key(s) for the CloudTrail bucket and other sensitive resources where appropriate") is satisfied incrementally as each stack is built, rather than as one central "encryption stack" — encryption is a property of the specific resource, not a separate layer:

| Resource | Key | Rationale for a *dedicated* key (vs. sharing one) |
|---|---|---|
| VPC Flow Logs (CloudWatch Logs) | `nb-exercise/vpc-flow-logs` | Scoped key policy — only principals that need flow-log access get key access. |
| CloudTrail S3 bucket | `nb-exercise/cloudtrail` | Same reasoning — a widened grant on one key (e.g., for a SIEM integration) shouldn't implicitly widen access to the other log type. |
| EC2 EBS volume *(next section)* | to be added | Root/data volume for the SSM-managed instance. |
| SNS security alerts | AWS-managed (`aws/sns`) | Deliberately *not* a CMK — see above. Not every encrypted resource needs a customer-managed key; that's a decision, not an oversight. |

## 5. Identity (`IdentityStack`)

| Decision | Rationale |
|---|---|
| Exactly two roles: `nb-exercise-breakglass-admin` and `nb-exercise-security-auditor`. No standing IAM users created | Matches the exercise's stated minimum. Role-only access means every session is temporary, named, and shows up as a distinct `AssumeRole` event in CloudTrail — there's no long-lived credential to leak in the first place. |
| Both roles' trust policies require `aws:MultiFactorAuthPresent: true` | MFA-gating is enforced at the trust-policy level, not left as an out-of-band "please remember to require MFA" note. An unauthenticated or MFA-less session literally cannot assume either role, regardless of what IAM policy would otherwise allow. |
| Break-glass: 1-hour max session duration; auditor: 4-hour | Break-glass is emergency-use — short-lived by design, forcing re-authentication (and a fresh MFA check) if the emergency runs long. Auditor sessions are longer since audit work is often a sustained task, but still bounded, not indefinite. |
| Every assumption of the break-glass role fires an EventBridge rule → the shared SNS alerts topic | Break-glass access should be rare and every use should be reviewed by a human, not just logged and forgotten. Tying detection to the *role*, not to hoping someone remembers to check CloudTrail, means the alert exists whether or not anyone thinks to look. |
| Root account hardening (MFA, no access keys, no routine use) is documented in the README as a required manual step, not modeled in CDK | IaC can't reach into the account's root credentials — this is an honest boundary, not a gap I'm hiding. Better to say explicitly "this is manual, do it first" than to imply CDK covers it. |

## 6. Secure Access (`ComputeStack`)

| Decision | Rationale |
|---|---|
| Instance role has exactly `AmazonSSMManagedInstanceCore` — nothing else attached | This is the SSM agent's own operating requirement, not a stand-in for "give the instance broad access because it's easier." If the instance ever needs to touch another AWS service, that's a deliberate, reviewable addition to this role — not an assumption baked in up front. |
| `require_imdsv2=True` on the instance | Closes the SSRF→instance-credential-theft path at the platform level (the exact pattern behind the 2019 Capital One breach) rather than hoping nothing running on the box is vulnerable to SSRF. Cheap to set, easy to forget. |
| Security group: **zero inbound rules**, egress scoped to exactly VPC CIDR (443, for the SSM interface endpoints) + the region's S3 managed prefix list (443, for the gateway endpoint) | Session Manager needs no inbound rule at all — that's the entire point of it vs. SSH. Egress is the *precise* control here (as opposed to the NACL, which is deliberately coarser — see the Networking correction above); verified in the synthesized template that the S3 rule resolves to a `DestinationPrefixListId`, not a CIDR guess. |
| EBS volume and the SSM session-log CloudWatch group share one CMK (`nb-exercise/compute`), diverging from the flow-logs/CloudTrail one-key-per-log-type pattern | Both protect data tied to the same instance/session boundary, and the people who'd need access (security/ops reviewing this one box) are the same population — a 4th dedicated key for a single-instance exercise doesn't earn its complexity. Would split them if session-log and EBS-restore access ever needed to diverge (e.g., a larger fleet where different teams own different concerns). |
| SSM Session Manager logging enabled account/region-wide via the `SSM-SessionManagerRunShell` document — session I/O streams to an encrypted CloudWatch Logs group, 20-min idle timeout, 60-min max session duration | "No inbound SSH" closes one gap; without this, there'd still be zero record of *what was actually done* in a session — which is exactly what an auditor or incident responder needs after the fact. The timeouts bound how long a session can sit open, win or lose. |

## 7. Configuration Monitoring (`ComplianceStack`)

| Decision | Rationale |
|---|---|
| **AWS Config, not Security Hub + CIS** | CIS Foundations turns on 50+ checks at once, most unrelated to anything actually built here. A curated Config rule set — one rule per control this exercise deliberately implements — tells a more precise story: "here's how we'd know if any of these specific controls drifted or got weakened," not a generic best-practices checklist bolted on at the end. The more defensible reading of "quality over volume." |
| 8 managed rules, each mapped to a specific requirement already built: root MFA + no root access keys (Identity), CloudTrail enabled (Logging), GuardDuty enabled (Threat Detection), EBS volumes encrypted (Encryption), no incoming SSH (Secure Access), S3 no public read/write (the CloudTrail bucket staying private) | Every rule answers "how would we know if *this specific thing* silently regressed" — not "AWS's opinion of a generic best practice." That mapping is also the fastest way to explain the whole rule set in the walkthrough: point at each requirement, name its rule. |
| Config delivers into the *existing* CloudTrail bucket, under a `config/` prefix, reusing its encryption/versioning/access-block posture | Same reasoning as not adding a 4th CMK in Compute: a second audit-artifact bucket for the same consumer population (security/compliance review) is sprawl without benefit. |
| Config's IAM role is granted access to the bucket/key via a **pseudo-parameter-only ARN string** (`Aws.PARTITION`/`Aws.ACCOUNT_ID` + a fixed role name), not via `role.role_arn` or CDK's `.grant_*()` helpers | **Caught during the build:** using the grant helpers here creates a genuine cross-stack dependency cycle — ComplianceStack already depends on LoggingStack for the bucket/key, and the grant helpers would make LoggingStack's policies depend back on ComplianceStack's role. CDK correctly refuses to synthesize that. A manually-constructed ARN (same account, explicit fixed role name, no live stack reference) grants the identical access without creating the cycle — worth explaining in the walkthrough as another real issue caught before deployment, not a workaround for a code smell. |

## 8. Evolving to a Multi-Account Strategy

Everything above lives in one account because the exercise provides one account. That's the right scope for this exercise — but it's explicitly *not* the target state for a regulated environment, and it's worth being precise about what changes and why, not just naming "Organizations + Control Tower" and moving on.

### Why single-account doesn't hold up

The single biggest gap: in this account, the same humans who operate workloads can also (via the break-glass role) touch the logging/security controls that would need to catch them misbehaving. Blast radius is unbounded — a mistake or compromise anywhere in this account can reach everything else in it. That's the core problem multi-account solves: **security boundaries become account boundaries**, which are far harder to accidentally cross than an IAM policy boundary within one account.

### Target structure

- **Management account** — hosts AWS Organizations + Control Tower landing zone only. No workloads, no human daily-driver access. Its whole job is establishing guardrails and vending accounts.
- **Security OU**
  - **Log Archive account** — the *only* place CloudTrail, Config, and VPC Flow Log data ultimately lands, via an **Organization Trail** (one trail, applies to every account, created from the management account, member accounts can't disable or modify it). This is this exercise's `LoggingStack` bucket, but centralized and immutable from every other account's perspective.
  - **Security Tooling account** — delegated administrator for GuardDuty, Security Hub, and Config (AWS supports delegating these to a non-management account, which you should — keeping the management account's blast radius minimal). This account runs a **Config Aggregator** and **Security Hub cross-account/cross-region aggregation** pulling findings from every member account, and owns the SNS/EventBridge pipeline this exercise's `SecurityStack` seeded — at org scale that pipeline should feed a ticketing system or SOAR, not just a topic.
- **Infrastructure OU** — shared networking (Transit Gateway or similar), CI/CD accounts.
- **Workloads OU** — per-environment or per-team accounts (dev/staging/prod, or per-application), each provisioned via **Control Tower Account Factory** so every new account inherits the same baseline (org trail enrollment, GuardDuty enrollment, default SCPs) automatically — no per-account bootstrapping checklist to forget.
- **Sandbox OU** — for exploration/exercises like this one, with looser guardrails but still enrolled in the org trail.

### What moves from IAM policy to Service Control Policy

This exercise enforces things like "no incoming SSH" and "GuardDuty must stay enabled" via *detective* Config rules — we find out after the fact if someone disabled them. At org scale, the highest-value controls become **preventive** SCPs attached at the OU level, so member-account admins (even with `AdministratorAccess` in their own account) *cannot* take the action at all:
- Deny disabling GuardDuty, Config, or CloudTrail
- Deny leaving the Organization
- Deny overriding S3 Block Public Access settings
- Deny use of IAM users/access keys where the org standard is IAM Identity Center + roles only
- Require IMDSv2 (deny `RunInstances` without it)

Config rules don't disappear — they become the check that *catches* anything SCPs don't cover, and the audit evidence that the preventive controls actually held.

### What changes about identity

This exercise's two roles (break-glass admin, security auditor) were built account-locally because that's all there is. At org scale:
- Human access moves to **IAM Identity Center** (management account), with **permission sets** assigned per-account/per-OU — nobody has a standing IAM user in any member account, ever.
- Break-glass becomes an org-level concern: a small number of tightly-controlled permission sets, MFA-required, session-limited, usable across accounts in an emergency, with the same "every use alerts" pattern this exercise already builds — just fed into the centralized Security Tooling account's pipeline instead of a single account's SNS topic.
- Each workload account still gets its own least-privilege roles for its own workloads (this exercise's `ComputeStack` instance role is a fine pattern at any scale) — that part doesn't change, it's the *human* access model that centralizes.

### What I'd genuinely reconsider, not just scale up

- **One CloudTrail per account vs. the org trail** — the org trail is non-negotiable for the guarantee that member accounts can't tamper with their own trail. But per-account CloudWatch Logs streaming (this exercise's near-real-time search capability) still makes sense to keep local for each account's own team, in addition to the org trail's S3 delivery.
- **KMS key strategy** — this exercise uses 3-4 account-local CMKs. At org scale, whether Log Archive's bucket key is shared across all contributing accounts (simpler, but couples key policy management to one team) or per-source-account (matches this exercise's "scoped by principal population" reasoning, but more keys to manage) is a real trade-off, not an obvious answer — I'd want to know the security team's actual operating model before picking.
- **IaC deployment model** — CDK apps deploying into dozens of accounts needs a pipeline account with cross-account deployment roles (or CDK Pipelines / a dedicated tool), not a person running `cdk deploy` locally against each account. That's infrastructure this exercise doesn't need but a real rollout would need on day one.

### Bootstrap sequence — Organizations + Control Tower (reference only, not deployed)

**This section is design material for the write-up and walkthrough. It was not deployed against the exercise account.** Enabling Control Tower creates a real AWS Organization and auto-provisions two new member accounts (Log Archive, Audit) — that's an org-wide, semi-permanent commitment, not something to test-drive in a throwaway account. The sequence below reflects what I'd actually do with a dedicated management account:

1. **Stand up a clean management account.** Organizations and Control Tower both expect an account with no workloads and none planned — the exercise account can't become the management account after the fact; its resources would migrate into a Workloads-OU account instead.
2. **Enable Control Tower's landing zone** via the console wizard for first-time setup. It auto-creates the Log Archive and Audit accounts, an org-wide CloudTrail trail, an AWS Config aggregator, and enables IAM Identity Center. (Control Tower does expose an `AWS::ControlTower::LandingZone` / `aws_controltower.CfnLandingZone` CloudFormation resource, but AWS's own guidance is to use the wizard for the *initial* landing zone — it orchestrates account creation and email verification behind the scenes in ways worth letting AWS manage the first time.)
3. **Extend the OU structure.** Control Tower creates a Security OU (Log Archive + Audit) by default; add Infrastructure, Workloads, and Sandbox OUs on top. This part is genuinely code-manageable:

   ```python
   from aws_cdk import aws_organizations as organizations

   workloads_ou = organizations.CfnOrganizationalUnit(
       self, "WorkloadsOu",
       name="Workloads",
       parent_id=root_id,  # from CfnOrganization, or looked up
   )
   sandbox_ou = organizations.CfnOrganizationalUnit(
       self, "SandboxOu",
       name="Sandbox",
       parent_id=root_id,
   )
   ```

4. **Attach preventive guardrails (SCPs) per OU.** The deny-list from earlier in this section (disable GuardDuty/Config/CloudTrail, leave the org, override S3 Block Public Access, use IAM users instead of Identity Center) as `aws_organizations.CfnPolicy`, attached at the OU level:

   ```python
   deny_disable_security_services = organizations.CfnPolicy(
       self, "DenyDisableSecurityServices",
       name="deny-disable-security-services",
       type="SERVICE_CONTROL_POLICY",
       content={
           "Version": "2012-10-17",
           "Statement": [{
               "Sid": "DenyDisablingSecurityServices",
               "Effect": "Deny",
               "Action": [
                   "guardduty:DeleteDetector",
                   "guardduty:DisassociateFromMasterAccount",
                   "config:DeleteConfigurationRecorder",
                   "config:StopConfigurationRecorder",
                   "cloudtrail:DeleteTrail",
                   "cloudtrail:StopLogging",
               ],
               "Resource": "*",
           }],
       },
   )
   deny_disable_security_services.add_target(workloads_ou.attr_id)
   ```

   Layer Control Tower's own "strongly recommended" and "elective" controls on top via `aws_controltower.CfnEnabledControl` (e.g., requiring IMDSv2, blocking internet-routable VPCs), scoped to the Workloads OU. The shift this represents: in the single-account exercise, "no incoming SSH" and "GuardDuty stays enabled" are things AWS Config *notices after the fact*. An SCP like the one above makes it something account admins *cannot do at all*, even with `AdministratorAccess` in their own account.
5. **Delegate security-tooling administration to the Audit account** — register it as delegated administrator for GuardDuty, Security Hub, and Config via Organizations' `RegisterDelegatedAdministrator`, so the management account stays minimal and one account owns cross-account visibility.
6. **Set up account vending** via Control Tower's built-in Account Factory (Service Catalog-based), or **Account Factory for Terraform (AFT)** for a fully code-driven version. AFT is the more credible answer if pressed on "how would you actually automate account creation" — Control Tower's built-in Account Factory is Service-Catalog-based and less naturally version-controlled. Either way, every new workload account should come out already enrolled in the org trail, GuardDuty, and the OU's SCPs, with zero manual bootstrapping.
7. **Re-scope this exercise's six stacks into a workload-account template** — this repo becomes the pattern stamped into every new Workloads-OU account, minus what Control Tower now owns centrally:

   | Stack | What changes |
   |---|---|
   | `NetworkingStack` | Unchanged — genuinely per-workload-account territory |
   | `LoggingStack` | Its CloudTrail becomes redundant with the org trail Control Tower creates automatically. Keep the CloudWatch Logs streaming (fast local search); drop the per-account trail-to-S3 delivery — that's the Log Archive account's job now |
   | `SecurityStack` | GuardDuty enrollment moves to organization-wide auto-enrollment from the Audit account, not a per-account `CfnDetector`. The alerting pattern (SNS + EventBridge) stays, but feeds the centralized pipeline instead of a per-account topic |
   | `IdentityStack` | Retired in favor of Identity Center permission sets — same MFA/session/alerting properties, centrally administered |
   | `ComputeStack` | Unchanged — exactly the kind of least-privilege, workload-scoped pattern that should stay local to each account |
   | `ComplianceStack` | Config recorder still runs per-account (that part doesn't centralize), but delivery/aggregation moves to the Audit account's Config Aggregator instead of this account's own bucket |

8. **Migrate identity from account-local IAM roles to Identity Center permission sets** — retire the break-glass/auditor IAM roles in favor of permission sets assigned per-account through IAM Identity Center in the management account, keeping the same MFA-required, session-limited, alert-on-use pattern, just centrally administered instead of duplicated per account.

## 9. CNAPP and EDR — Where Wiz/Orca and CrowdStrike Fit

GuardDuty (§3) and Config (§7) are AWS-native and account-scoped. Neither replaces a CNAPP or an EDR agent — they cover different layers, and it's worth being precise about which layer each one owns rather than treating "we have GuardDuty" as if it closes this topic.

### Where a CNAPP (Wiz / Orca) adds a layer this design doesn't have

GuardDuty tells you about active threats; Config tells you a specific resource drifted from a specific rule. Neither one *connects the dots across resources* — a CNAPP's actual value is graph-based attack-path analysis: "this public-facing thing can reach this role, which can reach this bucket with sensitive data" — the toxic-combination class of finding that no single-resource check catches, because no individual piece of it is wrong on its own. That's the gap a CNAPP fills here, plus broader agentless posture scanning (CVEs in installed packages, secrets in EBS snapshots, IAM entitlement analysis) than an 8-rule curated Config set is trying to be.

**Onboarding pattern**, consistent with how every agentless CNAPP actually connects to AWS: a dedicated cross-account IAM role, read-only, with an **external ID** to prevent confused-deputy attacks — the same shape as this exercise's `nb-exercise-security-auditor` role, but I would **not** reuse that role for it. The CNAPP vendor is a third-party external principal, not a human; keeping it a separate role means clean CloudTrail attribution (was this Config/S3 read our auditor or Wiz's scanner?) and means if the vendor's own environment is ever compromised, there's exactly one distinguishable role to revoke, not something shared with human access.

At the multi-account scale from §8, this role gets deployed via a **CloudFormation StackSet** targeting the Workloads/Sandbox OUs (StackSets' AWS Organizations integration needs trusted access activated once from the management account) — the same "baked into account vending, not bolted on per-account afterward" philosophy as everything else in §8. I'd also add an SCP protecting the role's name from modification/deletion by workload-account admins — Wiz's own published guidance recommends exactly this pattern, and it's a direct extension of the `DenyDisableSecurityServices` SCP already in §8: don't just prevent disabling GuardDuty/Config, prevent tampering with the third-party visibility layer too.

**Findings routing:** both Wiz and Orca support native EventBridge integration, so findings *could* feed the same `SecurityStack` SNS topic pattern this exercise already builds. In practice I'd lean toward the CNAPP's own alerting/ticketing integration instead — that's more mature than anything I'd build by hand — but the EventBridge path is real and worth mentioning as the "one pane of glass" option if that's a stated priority.

### Getting CrowdStrike Falcon onto every backend EC2 instance

Four pieces, and one genuine tension worth surfacing rather than glossing over:

1. **Bake it into the golden AMI**, not into user-data at boot. EC2 Image Builder (or Packer) with the Falcon sensor pre-installed; the CID (Customer ID) gets injected at boot from SSM Parameter Store rather than baked into the image, so one golden AMI works across dev/staging/prod with different CIDs and rotating a CID never means rebaking. In this repo, `ComputeStack`'s `ec2.MachineImage.latest_amazon_linux2023()` becomes a lookup against an SSM parameter pointing at the latest approved golden AMI.
2. **SSM State Manager (an Association) as the enforcement backstop** — targeting instances by tag, running on a recurring schedule to verify the sensor is present and running, self-healing if it's ever removed or disabled. This is also the install mechanism for anything not yet on the golden AMI.
3. **Drift detection through the same Config pattern already built.** There's no AWS-managed Config rule for "a third-party EDR sensor is running" — but SSM Inventory catalogs installed software per instance, and a custom Lambda-backed Config rule can evaluate against that inventory. That's a 9th rule added to `ComplianceStack`, consistent with the existing "one rule per control we actually care about" philosophy, not a bolted-on afterthought. Config Remediation can trigger an SSM Automation to reinstall — or quarantine the instance into an isolated security group — if it's missing past a grace period.
4. **IAM instance role stays minimal — Falcon's own privilege model is separate from it.** Falcon's actual protection runs at the kernel/host level (driver hooks), not through AWS IAM — a common point of confusion worth being precise about in the walkthrough. If Falcon's cloud-facing features need to call AWS APIs (tagging, enrichment), that's a narrowly scoped addition to the existing SSM-only instance role — not a new blanket grant. Same "exactly what's needed" philosophy as everything else in `ComputeStack`.

**The real tension: this exercise's NAT-less network design.** Falcon needs outbound connectivity to CrowdStrike's cloud for sensor telemetry — and this exercise's private subnet has zero route to the internet by design (§1). Two resolutions, and they apply at different scales:

- **For this exercise's single instance:** CrowdStrike genuinely supports **AWS PrivateLink** for Falcon sensor traffic, including a newer cross-region model that removes the old same-region-as-your-CID requirement. That's the option consistent with everything already built here — add a Falcon-specific interface VPC endpoint the exact same way the SSM/EC2Messages/SSMMessages endpoints were added in `NetworkingStack`, with a Route 53 private hosted zone aliasing the `cloudsink.net` sensor hostnames to it (PrivateLink for Falcon is DNS-driven, not IP-driven). The "no NAT" decision holds up even with an EDR agent in the picture — it just needs one more endpoint.
- **At the multi-account scale from §8:** the more sustainable pattern is a shared egress/inspection VPC in the Infrastructure OU, reachable via Transit Gateway, rather than every workload account punching its own PrivateLink or NAT hole for every third-party integration it accumulates over time.

Worth knowing for the walkthrough: CrowdStrike explicitly markets native Control Tower integration via API for account-scale onboarding — directly relevant if asked "how does this scale to every account," and it's the same "onboard at vending time" answer as the CNAPP role above, not a coincidence — it's the same architectural pattern applied twice.

## 10. What I'd Do With More Time

In the interest of being direct about scope, not just what got built:

- **No S3 export for GuardDuty/Config findings beyond their native retention** — fine for an exercise, wrong for production evidence retention.
- **Single NAT-less design was validated by synthesis, not a live deployment** — I'd want to actually exercise a Session Manager connection and confirm patch-repo reachability end-to-end before calling the "no NAT" decision fully proven, not just structurally sound.
- **No automated tests** (e.g., CDK assertions/snapshot tests) — reasonable for a scoped exercise, would be a gap in anything longer-lived.
- **SCPs and multi-account aren't implemented, only designed** — correctly out of scope for a single provided account, but worth being upfront that Section 8 is a plan, not code.
- **CNAPP and CrowdStrike (§9) are also design-only** — no Wiz/Orca account, no CrowdStrike CID, and neither was set up against the exercise account. Same reasoning as §8: this answers what was asked ("where would you add X"), not "here's X running."



