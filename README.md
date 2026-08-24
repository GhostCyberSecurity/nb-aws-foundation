# Secure AWS Foundation — nb-exercise

A focused, production-minded secure AWS foundation, built for the Northeast Bank
technical exercise. Full reasoning behind every control is in
[`DESIGN_DECISIONS.md`](./DESIGN_DECISIONS.md) — start there for "why," this file
is "how." Prepping for the live walkthrough itself — [`WALKTHROUGH_PREP.md`](./WALKTHROUGH_PREP.md)
has likely questions with short answer anchors, organized to match the design doc.

## What's here

| Stack | Covers |
|---|---|
| `NbExercise-Networking` | Multi-AZ VPC, subnets, VPC endpoints, NACLs, flow logs |
| `NbExercise-Logging` | Multi-region CloudTrail → encrypted/versioned/private S3, CMK |
| `NbExercise-Security` | GuardDuty + shared security-alerts SNS topic |
| `NbExercise-Identity` | Break-glass admin role, security-auditor role (both MFA-gated) |
| `NbExercise-Compute` | SSM-managed EC2 instance, no inbound, session logging |
| `NbExercise-Compliance` | AWS Config, 8 curated rules mapped to the controls above |

Architecture diagram: [`docs/architecture.svg`](./docs/architecture.svg).

## Prerequisites

- Python 3.9+ and `pip`
- Node.js 18+ (for the CDK CLI)
- AWS CDK CLI: `npm install -g aws-cdk` (this repo was built/validated against `2.1138.0`)
- AWS credentials for the exercise account, configured however you prefer —
  `aws configure`, an SSO profile (`aws sso login --profile <profile>`), or
  environment variables. The CDK CLI picks these up automatically; you don't
  need to hardcode an account/region anywhere in this repo.
- **Root account hardening is a manual, one-time step, not something this repo
  automates** (see `DESIGN_DECISIONS.md` §5): before anything else, confirm the
  root user has MFA enabled and no access keys, and isn't the credential set
  you're deploying with.

## First-time setup

```bash
git clone <this-repo> && cd nb-aws-foundation
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# One-time per account/region - creates the CDK bootstrap resources
# (an S3 bucket + IAM roles CDK uses to deploy). Safe to re-run.
cdk bootstrap
```

## Deploy

```bash
# See what will change before deploying anything
cdk diff

# Deploy everything - CDK resolves the dependency order automatically
# (Networking/Logging/Security before Identity/Compute/Compliance, since
# those depend on the VPC, the alerts topic, and the CloudTrail bucket/key)
cdk deploy --all
```

You'll be prompted to approve IAM/security-group changes per stack on first
deploy (`--require-approval` is on by default) — expected, since several
stacks create IAM roles and security groups.

**If you'd rather deploy incrementally to watch each piece land** (useful for
the walkthrough itself), deploy in this order — this is also the dependency
order CDK would infer automatically:

```bash
cdk deploy NbExercise-Networking
cdk deploy NbExercise-Logging
cdk deploy NbExercise-Security
cdk deploy NbExercise-Identity
cdk deploy NbExercise-Compute
cdk deploy NbExercise-Compliance
```

### A note on the SSM Session Manager preferences document

`ComputeStack` creates an SSM document named `SSM-SessionManagerRunShell`. This
name is special — it's the account/region-wide default Session Manager
preferences document, not a resource scoped to this stack. If your account
already has one (unlikely in a fresh exercise account, but worth checking:
`aws ssm get-document --name SSM-SessionManagerRunShell`), this deploy will
overwrite its settings rather than fail, since the document already exists. If
that's not what you want, rename this resource before deploying.

## Verify

```bash
# Confirm the instance is live and SSM-managed
aws ec2 describe-instances --filters "Name=tag:Name,Values=*ManagedInstance*" \
  --query "Reservations[].Instances[].{Id:InstanceId,State:State.Name,PublicIp:PublicIpAddress}"

# Connect - no SSH, no bastion, no key pair
aws ssm start-session --target <instance-id>

# Confirm no public IP (should return "None" / null)
# Confirm GuardDuty is enabled
aws guardduty list-detectors

# Confirm Config is recording
aws configservice describe-configuration-recorder-status
```

Session activity should show up in CloudWatch Logs under
`/ssm/session-logs/nb-exercise` within a minute or two of connecting.

## Cost notes

This design deliberately avoids the largest common cost driver (NAT Gateway —
see `DESIGN_DECISIONS.md` §1). Remaining non-free-tier costs, all modest for a
short-lived exercise account:

- 4 KMS CMKs (~$1/mo each, prorated to days actually deployed)
- 3 VPC interface endpoints × 2 AZs (~$0.01/hr each while running)
- 1 `t3.micro` instance + 8GB GP3 EBS
- GuardDuty, Config, and CloudTrail S3-data-event charges scale with activity,
  which will be minimal in a scoped exercise

## Teardown

```bash
cdk destroy --all
```

Confirm each stack when prompted. This repo is built so `cdk destroy` actually
finishes cleanly rather than leaving orphaned resources behind:

- The CloudTrail/Config S3 bucket has `auto_delete_objects=True`, so it empties
  itself before deletion (this is an **exercise-only convenience** —
  `DESIGN_DECISIONS.md` §2 flags why a production deployment would never do
  this to a compliance log bucket).
- The EBS volume has `delete_on_termination=True`.
- All KMS keys and CloudWatch Log groups have `RemovalPolicy.DESTROY`.

**After `cdk destroy --all` completes, verify manually** (belt-and-suspenders —
IaC destroy is reliable but "leave the account clean" is worth double-checking
directly, not just trusting the tool):

```bash
aws cloudformation list-stacks --stack-status-filter DELETE_FAILED
aws s3 ls | grep nbexercise   # should return nothing
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running,stopped"
```

If anything is left over, it's almost always because a resource outside this
repo's stacks (e.g., a manually-created SSM session log you opened, or a
CloudTrail-delivered object created after `auto_delete_objects` ran its
pre-delete sweep) needs a manual cleanup pass.
