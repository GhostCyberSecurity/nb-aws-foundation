from aws_cdk import Stack, aws_config as config, aws_iam as iam, aws_s3 as s3, aws_kms as kms
from constructs import Construct


class ComplianceStack(Stack):
    """
    Configuration monitoring (requirement #7): AWS Config, chosen over
    Security Hub + CIS for this exercise.

    Design decisions (see DESIGN_DECISIONS.md):
      - AWS Config, not Security Hub/CIS: CIS Foundations turns on ~50+
        checks at once, most unrelated to what we actually built. A
        curated Config rule set - one rule per control we deliberately
        implemented - tells a more precise story: "here's how we'd know
        if any of these specific controls drifted or got weakened,"
        rather than a generic best-practices checklist. This is the more
        defensible reading of "quality over volume of resources."
      - Delivers into the *existing* CloudTrail bucket (different prefix),
        reusing its encryption/versioning/access-block posture rather than
        standing up a second bucket for a second audit-artifact type with
        the same consumer population (security/compliance review).
      - The Config role's access to the bucket/key is granted via an
        IDENTITY policy on config_role itself (referencing the bucket/key's
        real ARNs), not a resource policy statement added to LoggingStack's
        bucket/key. This replaced an earlier approach that added a resource
        policy statement naming config_role's ARN on trail_key - which
        synthesized fine but FAILED at real deploy time: KMS validates that
        IAM principal ARNs in a key's resource policy correspond to
        existing entities at the moment the policy is applied, and
        config_role doesn't exist yet when LoggingStack deploys (Compliance
        depends on Logging, not the reverse). S3 bucket policies are far
        more lenient about this and likely would have tolerated it, but
        KMS specifically won't - caught via a real `cdk deploy`, not `cdk
        synth`. The identity-policy approach avoids the problem entirely:
        our KMS key's default policy already grants the account root full
        access, so any IAM identity policy granting an action on the key is
        sufficient - no resource-policy statement naming the principal is
        required. Referencing trail_bucket/trail_key's ARNs here is a
        normal one-way reference in the same direction Compliance already
        depends on Logging - not a new cycle, unlike the reverse would be.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        trail_bucket: s3.IBucket,
        trail_key: kms.IKey,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        config_role = iam.Role(
            self,
            "ConfigRole",
            role_name="nb-exercise-config-role",
            assumed_by=iam.ServicePrincipal("config.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWS_ConfigRole"
                )
            ],
        )

        # Granted on config_role's own identity policy, not on the bucket's/
        # key's resource policy - see class docstring for why.
        config_role.add_to_policy(
            iam.PolicyStatement(
                sid="AllowConfigWriteSnapshots",
                actions=["s3:PutObject"],
                resources=[f"{trail_bucket.bucket_arn}/config/AWSLogs/{self.account}/Config/*"],
            )
        )
        config_role.add_to_policy(
            iam.PolicyStatement(
                sid="AllowConfigGetBucketAcl",
                actions=["s3:GetBucketAcl"],
                resources=[trail_bucket.bucket_arn],
            )
        )
        config_role.add_to_policy(
            iam.PolicyStatement(
                sid="AllowConfigEncrypt",
                actions=["kms:GenerateDataKey*", "kms:Encrypt"],
                resources=[trail_key.key_arn],
            )
        )

        recorder = config.CfnConfigurationRecorder(
            self,
            "Recorder",
            role_arn=config_role.role_arn,
            recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
                all_supported=True,
                include_global_resource_types=True,
            ),
        )

        delivery_channel = config.CfnDeliveryChannel(
            self,
            "DeliveryChannel",
            s3_bucket_name=trail_bucket.bucket_name,
            s3_key_prefix="config",
            s3_kms_key_arn=trail_key.key_arn,
            config_snapshot_delivery_properties=config.CfnDeliveryChannel.ConfigSnapshotDeliveryPropertiesProperty(
                delivery_frequency="TwentyFour_Hours"
            ),
        )
        # Deliberately NO explicit dependency between recorder and
        # delivery_channel, in either direction - tried both ways, both
        # failed at real deploy time. These two resources have a genuine
        # mutual dependency at the AWS API level: creating a DeliveryChannel
        # requires a ConfigurationRecorder to already exist, but creating a
        # ConfigurationRecorder makes CloudFormation immediately try to
        # START it, which requires a DeliveryChannel to already exist.
        # Forcing either order with `add_dependency` fails outright -
        # NoAvailableDeliveryChannelException one way,
        # NoAvailableConfigurationRecorderException the other. Per AWS's own
        # docs ("CloudFormation starts the recorder as soon as the delivery
        # channel is available"), leaving both resources undependent lets
        # CloudFormation's own orchestration resolve this correctly - a
        # documented CloudFormation-specific accommodation for this exact
        # resource pair. See DESIGN_DECISIONS.md.


        # --- Curated rule set: one rule per control we deliberately built ---
        rules = {
            # Identity / root hardening (req #6)
            "RootMfaEnabled": config.ManagedRuleIdentifiers.ROOT_ACCOUNT_MFA_ENABLED,
            "RootNoAccessKeys": config.ManagedRuleIdentifiers.IAM_ROOT_ACCESS_KEY_CHECK,
            # Logging (req #2)
            "CloudTrailEnabled": config.ManagedRuleIdentifiers.CLOUD_TRAIL_ENABLED,
            # Threat detection (req #3)
            "GuardDutyEnabled": config.ManagedRuleIdentifiers.GUARDDUTY_ENABLED_CENTRALIZED,
            # Encryption (req #4)
            "EbsVolumesEncrypted": config.ManagedRuleIdentifiers.EBS_ENCRYPTED_VOLUMES,
            # Secure access (req #5) - flags drift toward open SSH
            "NoIncomingSsh": config.ManagedRuleIdentifiers.EC2_SECURITY_GROUPS_INCOMING_SSH_DISABLED,
            # CloudTrail bucket must stay private (req #2)
            "S3NoPublicRead": config.ManagedRuleIdentifiers.S3_BUCKET_PUBLIC_READ_PROHIBITED,
            "S3NoPublicWrite": config.ManagedRuleIdentifiers.S3_BUCKET_PUBLIC_WRITE_PROHIBITED,
        }

        for rule_id, identifier in rules.items():
            rule = config.ManagedRule(
                self,
                rule_id,
                identifier=identifier,
                config_rule_name=f"nb-exercise-{rule_id}",
            )
            rule.node.add_dependency(recorder)
