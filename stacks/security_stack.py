from aws_cdk import Stack, aws_guardduty as guardduty, aws_sns as sns, aws_events as events, aws_events_targets as targets
from constructs import Construct


class SecurityStack(Stack):
    """
    Threat detection (requirement #3) + shared security alerting.

    Design decisions (see DESIGN_DECISIONS.md):
      - GuardDuty enabled with 15-minute finding frequency (fastest option)
        rather than the 6-hour default, since this exercise benefits from
        fast feedback during testing and the walkthrough.
      - Malware Protection for EC2 is enabled given we do have an EC2
        instance in scope (req #5) - GuardDuty will scan its EBS volume
        if a suspicious finding triggers it.
      - No S3 export destination for findings: GuardDuty retains findings
        90 days natively, which comfortably covers this exercise's
        lifetime. A production deployment would export to S3/Security
        Lake for long-term retention and SIEM ingestion - documented as
        a forward-looking item, not built here, to keep this focused.
      - One SNS topic for security alerts, shared with IdentityStack for
        break-glass-role-assumption alerts. GuardDuty findings at
        severity >= 7 (HIGH) route here too. Consolidating "things a
        human needs to see right now" into one topic beats scattering
        alerting across each stack independently.
      - SNS topic uses the AWS-managed key (not a dedicated CMK): the
        messages are finding IDs/summaries and role-assumption metadata,
        not the underlying sensitive data itself, so a dedicated CMK's
        extra operational overhead isn't justified here. Worth revisiting
        if this topic ever carries higher-sensitivity payloads.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.detector = guardduty.CfnDetector(
            self,
            "Detector",
            enable=True,
            finding_publishing_frequency="FIFTEEN_MINUTES",
            features=[
                guardduty.CfnDetector.CFNFeatureConfigurationProperty(
                    name="S3_DATA_EVENTS", status="ENABLED"
                ),
                guardduty.CfnDetector.CFNFeatureConfigurationProperty(
                    name="EBS_MALWARE_PROTECTION", status="ENABLED"
                ),
            ],
        )

        self.alerts_topic = sns.Topic(
            self,
            "SecurityAlertsTopic",
            topic_name="nb-exercise-security-alerts",
            display_name="NB Exercise Security Alerts",
        )

        high_severity_rule = events.Rule(
            self,
            "GuardDutyHighSeverityRule",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"],
                detail={"severity": [{"numeric": [">=", 7]}]},
            ),
        )
        high_severity_rule.add_target(targets.SnsTopic(self.alerts_topic))

