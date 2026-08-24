from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_logs as logs,
    aws_kms as kms,
    aws_iam as iam,
)
from constructs import Construct


class NetworkingStack(Stack):
    """
    Multi-AZ VPC with public + fully-isolated private subnets.

    Design decisions (see DESIGN_DECISIONS.md for full rationale):
      - 2 AZs: HA minimum, cost-conscious per exercise notes.
      - Private subnets are PRIVATE_ISOLATED (no NAT, no IGW route at all),
        not PRIVATE_WITH_EGRESS. Reachability into AWS services is via
        VPC endpoints only.
      - VPC Flow Logs -> CloudWatch Logs, encrypted with a dedicated CMK,
        so control-plane network activity is captured from day one.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- VPC -------------------------------------------------------
        self.vpc = ec2.Vpc(
            self,
            "Vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
            max_azs=2,
            nat_gateways=0,  # deliberate - see design doc
            enable_dns_support=True,
            enable_dns_hostnames=True,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="private-isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                ),
            ],
        )

        # --- VPC Flow Logs ----------------------------------------------
        flow_log_key = kms.Key(
            self,
            "FlowLogKey",
            enable_key_rotation=True,
            alias="nb-exercise/vpc-flow-logs",
            removal_policy=RemovalPolicy.DESTROY,  # exercise account - see README teardown
        )

        # CloudWatch Logs needs explicit permission in the key's own policy to
        # use it - LogGroup's `encryption_key` param does not grant this
        # automatically. Missing this is a well-documented CDK gotcha, and
        # exactly the kind of thing only a real deployment catches, not
        # `cdk synth` - see DESIGN_DECISIONS.md.
        flow_log_key.add_to_resource_policy(
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
                        "kms:EncryptionContext:aws:logs:arn": f"arn:{self.partition}:logs:{self.region}:{self.account}:log-group:/vpc/flow-logs/{construct_id}"
                    }
                },
            )
        )

        flow_log_group = logs.LogGroup(
            self,
            "FlowLogGroup",
            log_group_name=f"/vpc/flow-logs/{construct_id}",
            retention=logs.RetentionDays.ONE_MONTH,
            encryption_key=flow_log_key,
            removal_policy=RemovalPolicy.DESTROY,
        )
        self.vpc.add_flow_log(
            "FlowLogAll",
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(flow_log_group),
            traffic_type=ec2.FlowLogTrafficType.ALL,
        )

        # --- VPC Endpoints (replace NAT for private-subnet reachability) ----
        self.vpc.add_gateway_endpoint(
            "S3Endpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED)],
        )

        endpoint_sg = ec2.SecurityGroup(
            self,
            "InterfaceEndpointSg",
            vpc=self.vpc,
            description="Allows HTTPS from within the VPC to interface endpoints only",
            allow_all_outbound=False,
        )
        endpoint_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(443),
            description="HTTPS from VPC CIDR",
        )

        for name, svc in {
            "SsmEndpoint": ec2.InterfaceVpcEndpointAwsService.SSM,
            "SsmMessagesEndpoint": ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
            "Ec2MessagesEndpoint": ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
            # Added after a real live-deployment test: Session Manager's
            # KMS-encrypted session logging (see ComputeStack) requires the
            # INSTANCE, not just the person starting the session, to reach
            # KMS and call kms:Decrypt during the session handshake. This
            # wasn't needed for agent registration, Run Command, or any of
            # the earlier checks - only an actual interactive `start-session`
            # attempt exercises it, which is exactly why it went unnoticed
            # until then. Without this endpoint, the NAT-less instance has
            # no network path to KMS at all, regardless of IAM permissions.
            "KmsEndpoint": ec2.InterfaceVpcEndpointAwsService.KMS,
        }.items():
            self.vpc.add_interface_endpoint(
                name,
                service=svc,
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                security_groups=[endpoint_sg],
                private_dns_enabled=True,
            )

        # --- Custom NACLs (defense-in-depth behind SGs) ------------------
        private_nacl = ec2.NetworkAcl(
            self,
            "PrivateNacl",
            vpc=self.vpc,
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
        )
        # HTTPS egress. NOTE: this is intentionally 0.0.0.0/0, not the VPC
        # CIDR - see DESIGN_DECISIONS.md. Traffic to the S3 gateway endpoint
        # resolves to real AWS-owned S3 IP ranges (via a managed prefix
        # list), not addresses inside the VPC. This CDK version's NetworkAcl
        # only accepts raw CIDR blocks (no prefix-list reference) - so a
        # VPC-CIDR-only NACL rule would silently break S3 reachability while
        # SSM-endpoint traffic kept working, which is a nasty thing to debug
        # after the fact. The NACL stays a coarse, protocol/port-level
        # control (443 only); the security group below is the precise
        # control, restricted to the VPC CIDR + the actual S3 prefix list.
        private_nacl.add_entry(
            "AllowEgressHttps",
            rule_number=100,
            cidr=ec2.AclCidr.any_ipv4(),
            traffic=ec2.AclTraffic.tcp_port(443),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )
        # Return traffic on ephemeral ports - same reasoning as above.
        # Left at its original rule number (100) deliberately - this rule
        # was already live in the deployed account, and changing a NACL
        # entry's rule number forces CloudFormation to replace it
        # (create-then-delete). A separate, unrelated new resource trying
        # to claim that same number while the old one's deletion is still
        # pending fails with AlreadyExists - a real ordering conflict hit
        # during deployment, resolved by never reusing an already-live
        # rule number instead of trying to sequence around the race.
        private_nacl.add_entry(
            "AllowIngressEphemeral",
            rule_number=100,
            cidr=ec2.AclCidr.any_ipv4(),
            traffic=ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )
        # --- The two rules below were missing initially - caught only by a
        # real deployment, via VPC Flow Logs showing REJECT entries for
        # cross-AZ traffic to an interface endpoint's second ENI. ---
        #
        # This single NACL governs BOTH private-isolated subnets (one per
        # AZ). Traffic between resources in *different* AZs (e.g. this
        # instance in AZ-A reaching an interface endpoint's ENI that happens
        # to sit in AZ-B - which DNS can return, since endpoints have one
        # ENI per AZ) crosses two subnet boundaries, not one: egress out of
        # the source's subnet, then ingress INTO the destination's subnet -
        # governed by this same NACL on both sides. Same-AZ traffic never
        # hits this problem, because traffic within a single subnet never
        # crosses a NACL boundary at all (NACLs are subnet-boundary-based;
        # only security groups apply there) - which is exactly why this
        # gap wasn't visible until DNS happened to resolve cross-AZ.
        # Ingress on 443: needed for a NEW connection arriving at a
        # NACL-governed subnet (e.g. the endpoint ENI's subnet, receiving
        # the instance's SYN). Rule number 110 - deliberately fresh, never
        # used on this NACL before, for the same reason noted above.
        private_nacl.add_entry(
            "AllowIngressHttps",
            rule_number=110,
            cidr=ec2.AclCidr.any_ipv4(),
            traffic=ec2.AclTraffic.tcp_port(443),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )
        # Egress on ephemeral ports: needed for the RETURN traffic leaving
        # that same subnet, headed back to the originating instance's
        # ephemeral source port. Rule number 110 - also fresh.
        private_nacl.add_entry(
            "AllowEgressEphemeral",
            rule_number=110,
            cidr=ec2.AclCidr.any_ipv4(),
            traffic=ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )
        # Everything else is implicit deny (custom NACLs default-deny).

        public_nacl = ec2.NetworkAcl(
            self,
            "PublicNacl",
            vpc=self.vpc,
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )
        for direction in (ec2.TrafficDirection.EGRESS, ec2.TrafficDirection.INGRESS):
            public_nacl.add_entry(
                f"Allow{direction.value}Https",
                rule_number=100,
                cidr=ec2.AclCidr.any_ipv4(),
                traffic=ec2.AclTraffic.tcp_port(443),
                direction=direction,
                rule_action=ec2.Action.ALLOW,
            )
            public_nacl.add_entry(
                f"Allow{direction.value}Ephemeral",
                rule_number=110,
                cidr=ec2.AclCidr.any_ipv4(),
                traffic=ec2.AclTraffic.tcp_port_range(1024, 65535),
                direction=direction,
                rule_action=ec2.Action.ALLOW,
            )

        self.endpoint_sg = endpoint_sg
