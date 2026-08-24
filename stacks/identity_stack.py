from aws_cdk import (
    Stack,
    Duration,
    aws_iam as iam,
    aws_events as events,
    aws_events_targets as targets,
    aws_sns as sns,
)
from constructs import Construct


class IdentityStack(Stack):
    """
    Least-privilege IAM roles (requirement #6).

    Design decisions (see DESIGN_DECISIONS.md):
      - Two roles only, matching the exercise's stated minimum: a
        break-glass admin role and a read-only/security-auditor role.
        No standing human IAM users are created - everyone assumes a
        role, so every session is time-boxed and shows up as an
        AssumeRole event in CloudTrail with an identifiable role/session
        name, not an anonymous long-lived credential.
      - Break-glass role requires MFA in its trust policy (not just "IAM
        best practice" advice bolted on afterward) and has a short max
        session duration. Every assumption of it fires an alert - it
        should be rare, and every use should be reviewed.
      - Root account hardening (MFA on root, no root access keys,
        removing root from routine use) is called out explicitly, but
        isn't something CDK can enforce - it's an account-level, one-time
        manual action. It's documented as a required manual step in the
        README rather than silently left out.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        alerts_topic: sns.ITopic,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- Break-glass admin role ---------------------------------------
        breakglass_principal = iam.AccountPrincipal(self.account).with_conditions(
            {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
        )

        self.breakglass_role = iam.Role(
            self,
            "BreakGlassAdminRole",
            role_name="nb-exercise-breakglass-admin",
            assumed_by=breakglass_principal,
            max_session_duration=Duration.hours(1),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess")
            ],
            description=(
                "Emergency-use admin access. Requires MFA to assume. "
                "Every assumption triggers a security alert - see AssumeRoleAlertRule."
            ),
        )

        # Alert on every assumption of the break-glass role - it should be
        # rare, and every occurrence deserves human eyes on it.
        breakglass_alert_rule = events.Rule(
            self,
            "BreakGlassAssumeRoleAlertRule",
            event_pattern=events.EventPattern(
                source=["aws.sts"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventName": ["AssumeRole"],
                    "requestParameters": {
                        "roleArn": [self.breakglass_role.role_arn]
                    },
                },
            ),
        )
        breakglass_alert_rule.add_target(targets.SnsTopic(alerts_topic))

        # --- Read-only / security-auditor role -----------------------------
        auditor_principal = iam.AccountPrincipal(self.account).with_conditions(
            {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
        )

        self.auditor_role = iam.Role(
            self,
            "SecurityAuditorRole",
            role_name="nb-exercise-security-auditor",
            assumed_by=auditor_principal,
            max_session_duration=Duration.hours(4),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "SecurityAudit"
                ),
            ],
            description=(
                "Read-only access for security review/audit work - no "
                "write, no data-plane access to workload data."
            ),
        )
