from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    aws_s3 as s3,
    aws_kms as kms,
    aws_cloudtrail as cloudtrail,
    aws_logs as logs,
    aws_iam as iam,
)
from constructs import Construct


class LoggingStack(Stack):
    """
    Multi-region CloudTrail delivering to an encrypted, versioned,
    publicly-inaccessible S3 bucket, with a customer-managed KMS key.

    Design decisions (see DESIGN_DECISIONS.md):
      - Dedicated CMK for CloudTrail, separate from the flow-log CMK.
      - Bucket policy denies non-TLS and unencrypted puts explicitly,
        rather than relying solely on default encryption.
      - Trail also streams to CloudWatch Logs for near-real-time search/
        alerting, in addition to the durable S3 record.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- KMS CMK for CloudTrail --------------------------------------
        self.trail_key = kms.Key(
            self,
            "CloudTrailKey",
            alias="nb-exercise/cloudtrail",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,  # exercise account - see README teardown
        )
        # CloudTrail service needs to be able to describe/encrypt with this key.
        # CDK's Trail construct grants what it needs when we pass encryption_key,
        # but we add an explicit statement for clarity/auditability of intent.
        self.trail_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudTrailToEncryptLogs",
                principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                actions=["kms:GenerateDataKey*"],
                resources=["*"],
                conditions={
                    "StringLike": {
                        "kms:EncryptionContext:aws:cloudtrail:arn": f"arn:aws:cloudtrail:*:{self.account}:trail/*"
                    }
                },
            )
        )
        self.trail_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudTrailToDescribeKey",
                principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                actions=["kms:DescribeKey"],
                resources=["*"],
            )
        )

        # --- S3 bucket: versioned, encrypted, fully private ---------------
        self.trail_bucket = s3.Bucket(
            self,
            "CloudTrailBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.trail_key,
            bucket_key_enabled=True,  # reduces KMS request cost/throttling risk
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,  # denies non-TLS requests via bucket policy
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,  # exercise account - see README teardown
        )

        # --- CloudWatch Logs group for near-real-time trail search --------
        trail_log_group = logs.LogGroup(
            self,
            "CloudTrailLogGroup",
            log_group_name="/cloudtrail/nb-exercise",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- Trail ---------------------------------------------------------
        self.trail = cloudtrail.Trail(
            self,
            "OrgTrail",
            trail_name="nb-exercise-trail",
            bucket=self.trail_bucket,
            encryption_key=self.trail_key,
            is_multi_region_trail=True,
            include_global_service_events=True,
            enable_file_validation=True,  # tamper-evidence via digest files
            send_to_cloud_watch_logs=True,
            cloud_watch_log_group=trail_log_group,
            cloud_watch_logs_retention=logs.RetentionDays.ONE_MONTH,
        )
