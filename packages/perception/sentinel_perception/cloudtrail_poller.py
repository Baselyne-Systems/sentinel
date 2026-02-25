"""
CloudTrail Poller — polls CloudTrail lookup_events for resource-mutating events
and triggers targeted re-scans of affected resources.

Phase 1: Polling mode (every 60 seconds)
Phase 2 upgrade path: Replace with Kinesis/SQS event stream subscription
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

from sentinel_core.graph.client import Neo4jClient
from sentinel_perception.connectors.aws.base import get_session, run_sync
from sentinel_perception.graph_builder import GraphBuilder

logger = logging.getLogger(__name__)

# Events that indicate resource mutations requiring a re-scan
MUTATION_EVENTS: dict[str, str] = {
    # S3
    "CreateBucket": "S3Bucket",
    "DeleteBucket": "S3Bucket",
    "PutBucketAcl": "S3Bucket",
    "PutBucketPolicy": "S3Bucket",
    "PutPublicAccessBlock": "S3Bucket",
    # EC2 / Security Groups
    "AuthorizeSecurityGroupIngress": "SecurityGroup",
    "AuthorizeSecurityGroupEgress": "SecurityGroup",
    "RevokeSecurityGroupIngress": "SecurityGroup",
    "RevokeSecurityGroupEgress": "SecurityGroup",
    "CreateSecurityGroup": "SecurityGroup",
    "DeleteSecurityGroup": "SecurityGroup",
    "RunInstances": "EC2Instance",
    "TerminateInstances": "EC2Instance",
    # IAM
    "AttachRolePolicy": "IAMRole",
    "DetachRolePolicy": "IAMRole",
    "PutRolePolicy": "IAMRole",
    "DeleteRolePolicy": "IAMRole",
    "CreateRole": "IAMRole",
    "DeleteRole": "IAMRole",
    "AttachUserPolicy": "IAMUser",
    "DetachUserPolicy": "IAMUser",
    "CreateUser": "IAMUser",
    "DeleteUser": "IAMUser",
    "CreatePolicy": "IAMPolicy",
    "DeletePolicy": "IAMPolicy",
    # Lambda
    "CreateFunction20150331": "LambdaFunction",
    "UpdateFunctionConfiguration20150331v2": "LambdaFunction",
    "DeleteFunction20150331": "LambdaFunction",
    # RDS
    "CreateDBInstance": "RDSInstance",
    "ModifyDBInstance": "RDSInstance",
    "DeleteDBInstance": "RDSInstance",
}


class CloudTrailPoller:
    """
    Polls CloudTrail for mutation events and triggers targeted graph updates.

    Usage:
        poller = CloudTrailPoller(neo4j_client, account_id="123456789012", regions=["us-east-1"])
        await poller.start()      # starts background polling
        await poller.stop()       # stops gracefully
    """

    def __init__(
        self,
        neo4j_client: Neo4jClient,
        account_id: str,
        regions: list[str],
        poll_interval: int = 60,
        assume_role_arn: str | None = None,
    ) -> None:
        self._client = neo4j_client
        self._builder = GraphBuilder(neo4j_client)
        self._account_id = account_id
        self._regions = regions
        self._poll_interval = poll_interval
        self._assume_role_arn = assume_role_arn
        self._running = False
        self._task: asyncio.Task | None = None
        self._last_poll: datetime = datetime.now(timezone.utc) - timedelta(minutes=5)

    async def start(self) -> None:
        """Start the background polling loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info(
            "CloudTrail poller started for account %s (interval: %ds)",
            self._account_id,
            self._poll_interval,
        )

    async def stop(self) -> None:
        """Stop the polling loop gracefully."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("CloudTrail poller stopped")

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("CloudTrail poll error: %s", exc)
            await asyncio.sleep(self._poll_interval)

    async def _poll_once(self) -> None:
        """Poll CloudTrail for events since last poll and trigger re-scans."""
        now = datetime.now(timezone.utc)
        start_time = self._last_poll

        for region in self._regions:
            try:
                events = await self._fetch_events(region, start_time, now)
                if events:
                    logger.info(
                        "CloudTrail [%s]: %d mutation events since %s",
                        region,
                        len(events),
                        start_time.isoformat(),
                    )
                await self._process_events(events, region)
            except Exception as exc:
                logger.warning("CloudTrail poll failed for region %s: %s", region, exc)

        self._last_poll = now

    async def _fetch_events(
        self,
        region: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[dict[str, Any]]:
        """Fetch CloudTrail events for the given time window."""
        session = await asyncio.to_thread(
            get_session, region, self._assume_role_arn
        )
        ct = await run_sync(lambda: session.client("cloudtrail", region_name=region))

        def _lookup():
            paginator = ct.get_paginator("lookup_events")
            events = []
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                LookupAttributes=[
                    {"AttributeKey": "ReadOnly", "AttributeValue": "false"}
                ],
            ):
                events.extend(page.get("Events", []))
            return events

        return await run_sync(_lookup)

    async def _process_events(
        self, events: list[dict[str, Any]], region: str
    ) -> None:
        """Process CloudTrail events and trigger targeted re-scans."""
        seen_resources: set[tuple[str, str]] = set()  # (resource_id, resource_type)

        for event in events:
            event_name = event.get("EventName", "")
            resource_type = MUTATION_EVENTS.get(event_name)
            if not resource_type:
                continue

            # Extract affected resource ID from event
            resource_id = self._extract_resource_id(event, resource_type)
            if not resource_id:
                continue

            key = (resource_id, resource_type)
            if key in seen_resources:
                continue  # Deduplicate within this poll window
            seen_resources.add(key)

            logger.info(
                "CloudTrail: %s detected for %s (%s) in %s",
                event_name,
                resource_id,
                resource_type,
                region,
            )

            # Trigger targeted re-scan
            try:
                await self._builder.targeted_scan(
                    account_id=self._account_id,
                    resource_id=resource_id,
                    resource_type=resource_type,
                    region=region,
                    assume_role_arn=self._assume_role_arn,
                )
            except Exception as exc:
                logger.error(
                    "Targeted scan failed for %s (%s): %s",
                    resource_id,
                    resource_type,
                    exc,
                )

    def _extract_resource_id(
        self, event: dict[str, Any], resource_type: str
    ) -> str | None:
        """Extract the primary resource ID from a CloudTrail event."""
        # CloudTrail Resources field
        for resource in event.get("Resources", []):
            if resource.get("ResourceType", "").endswith(resource_type.replace("AWS::", "")):
                return resource.get("ResourceName")

        # Fallback: parse CloudTrailEvent JSON
        import json
        raw = event.get("CloudTrailEvent", "{}")
        try:
            ct_event = json.loads(raw)
            req = ct_event.get("requestParameters", {})

            # Per-type extraction
            extractors = {
                "S3Bucket": lambda r: r.get("bucketName") or r.get("bucket"),
                "SecurityGroup": lambda r: r.get("groupId"),
                "EC2Instance": lambda r: (
                    r.get("instancesSet", {})
                    .get("items", [{}])[0]
                    .get("instanceId")
                ),
                "IAMRole": lambda r: r.get("roleName"),
                "IAMUser": lambda r: r.get("userName"),
                "IAMPolicy": lambda r: r.get("policyArn"),
                "LambdaFunction": lambda r: r.get("functionName"),
                "RDSInstance": lambda r: r.get("dBInstanceIdentifier"),
            }
            extractor = extractors.get(resource_type)
            if extractor:
                return extractor(req)
        except (json.JSONDecodeError, KeyError, IndexError):
            pass

        return None
