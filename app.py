#!/usr/bin/env python3
import os
import aws_cdk as cdk

from stacks.networking_stack import NetworkingStack
from stacks.logging_stack import LoggingStack
from stacks.security_stack import SecurityStack
from stacks.identity_stack import IdentityStack
from stacks.compute_stack import ComputeStack
from stacks.compliance_stack import ComplianceStack

app = cdk.App()

env = cdk.Environment(
    account=app.node.try_get_context("account") or os.environ.get("CDK_DEFAULT_ACCOUNT"),
    region=app.node.try_get_context("region") or os.environ.get("CDK_DEFAULT_REGION") or "us-east-1",
)

networking = NetworkingStack(app, "NbExercise-Networking", env=env)
loggingstack = LoggingStack(app, "NbExercise-Logging", env=env)
security = SecurityStack(app, "NbExercise-Security", env=env)
identity = IdentityStack(
    app, "NbExercise-Identity", env=env, alerts_topic=security.alerts_topic
)
compute = ComputeStack(app, "NbExercise-Compute", env=env, vpc=networking.vpc)
compliance = ComplianceStack(
    app,
    "NbExercise-Compliance",
    env=env,
    trail_bucket=loggingstack.trail_bucket,
    trail_key=loggingstack.trail_key,
)

app.synth()
