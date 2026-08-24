from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_kms as kms,
    aws_logs as logs,
    aws_ssm as ssm,
)
from constructs import Construct


class ComputeStack(Stack):
    """
    Secure access (requirement #5): one EC2 instance, private subnet, no
    public IP, no inbound SSH - reachable only via SSM Session Manager.

    Design decisions (see DESIGN_DECISIONS.md):
      - Instance role has exactly AmazonSSMManagedInstanceCore - no other
        permissions. This is the SSM agent's own operating requirement,
        not a proxy for "give the instance broad access."
      - IMDSv2 is required (require_imdsv2=True) - closes the classic
        SSRF-to-credential-theft path (the pattern behind the 2019
        Capital One breach) at the instance level, not just "hope nothing
        on the box is vulnerable to SSRF."
      - Security group: zero inbound rules (SSM needs none), egress
        scoped to exactly the VPC CIDR (interface endpoints) + the
        region's S3 managed prefix list (gateway endpoint) on 443. This
        is the *precise* control - see NetworkingStack for why the NACL
        is deliberately coarser.
      - EBS volume and SSM session-log CloudWatch group share one CMK
        (`nb-exercise/compute`) rather than getting separate keys like
        the flow-log/CloudTrail split. Both protect data tied to the same
        instance/session boundary, and the access population (security/
        ops reviewing this one box) is the same - a 4th dedicated key for
        a single-instance exercise doesn't earn its complexity. Would
        reconsider if session-log and EBS-restore access populations
        diverge in a larger deployment.
      - SSM Session Manager logging is turned on account/region-wide via
        the SSM-SessionManagerRunShell document: every session's I/O
        streams to an encrypted CloudWatch Logs group. "No inbound SSH"
        closes one gap; without session logging there'd still be no
        record of *what was done* in a session. Idle timeout (20 min)
        and max duration (60 min) bound how long a session can sit open.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        vpc: ec2.IVpc,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- Shared CMK for this compute boundary --------------------------
        self.compute_key = kms.Key(
            self,
            "ComputeKey",
            alias="nb-exercise/compute",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,  # exercise account - see README teardown
        )

        # Same CloudWatch Logs + KMS requirement as NetworkingStack's flow
        # log key - the service needs explicit key-policy permission, which
        # LogGroup's encryption_key param does not grant on its own.
        self.compute_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogsToUseKey",
                principals=[iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")],
                actions=[
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                resources=["*"],
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": f"arn:{self.partition}:logs:{self.region}:{self.account}:log-group:/ssm/session-logs/nb-exercise"
                    }
                },
            )
        )

        # --- SSM session logging (account/region-wide preference) ---------
        session_log_group = logs.LogGroup(
            self,
            "SessionLogGroup",
            log_group_name="/ssm/session-logs/nb-exercise",
            retention=logs.RetentionDays.ONE_MONTH,
            encryption_key=self.compute_key,
            removal_policy=RemovalPolicy.DESTROY,
        )

        ssm.CfnDocument(
            self,
            "SessionManagerPreferences",
            document_type="Session",
            name="SSM-SessionManagerRunShell",
            content={
                "schemaVersion": "1.0",
                "description": "Regional Session Manager settings - nb-exercise",
                "sessionType": "Standard_Stream",
                "inputs": {
                    "cloudWatchLogGroupName": session_log_group.log_group_name,
                    "cloudWatchEncryptionEnabled": True,
                    "cloudWatchStreamingEnabled": True,
                    "kmsKeyId": self.compute_key.key_id,
                    "s3EncryptionEnabled": False,
                    "idleSessionTimeout": "20",
                    "maxSessionDuration": "60",
                    "runAsEnabled": False,
                },
            },
        )

        # --- Instance role: exactly what SSM needs, nothing else ----------
        instance_role = iam.Role(
            self,
            "InstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonSSMManagedInstanceCore"
                )
            ],
            description="SSM-only instance role - plus kms:Decrypt on compute_key, required for encrypted Session Manager sessions.",
        )
        # Required for interactive (not Run Command) Session Manager
        # sessions: AWS's own docs state that once KMS encryption is turned
        # on for session data, BOTH the person starting the session AND the
        # managed node itself need permission to use the key - the instance
        # side decrypts a data key as part of the handshake. This was never
        # exercised by agent registration or Run Command, which is exactly
        # why it went unnoticed until a real `start-session` attempt. Since
        # compute_key and instance_role are both owned by this same stack,
        # granting this directly is safe - no cross-stack cycle risk, unlike
        # the ComplianceStack situation where the key and the role were in
        # different stacks.
        self.compute_key.grant_decrypt(instance_role)

        # --- Security group: precise egress (VPC CIDR + S3 prefix list) ---
        s3_prefix_list = ec2.PrefixList.from_lookup(
            self,
            "S3PrefixList",
            prefix_list_name=f"com.amazonaws.{self.region}.s3",
        )

        instance_sg = ec2.SecurityGroup(
            self,
            "InstanceSg",
            vpc=vpc,
            description="SSM-managed instance - no inbound, egress limited to VPC endpoints + S3",
            allow_all_outbound=False,
        )
        instance_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(443),
            description="HTTPS to SSM interface endpoints",
        )
        instance_sg.add_egress_rule(
            peer=ec2.Peer.prefix_list(s3_prefix_list.prefix_list_id),
            connection=ec2.Port.tcp(443),
            description="HTTPS to S3 gateway endpoint (patch repos, SSM agent deps)",
        )
        # No ingress rules at all - Session Manager needs none.

        # --- Instance ------------------------------------------------------
        self.instance = ec2.Instance(
            self,
            "ManagedInstance",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(),
            role=instance_role,
            security_group=instance_sg,
            require_imdsv2=True,
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(
                        8,
                        encrypted=True,
                        kms_key=self.compute_key,
                        volume_type=ec2.EbsDeviceVolumeType.GP3,
                        delete_on_termination=True,  # exercise account - see README teardown
                    ),
                )
            ],
        )
