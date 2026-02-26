"""
PostureEvaluator — runs CIS rules against the Neo4j graph and stamps posture_flags.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sentinel_core.graph.client import Neo4jClient
from sentinel_core.knowledge.rules import ALL_RULES, CISRule

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A single CIS rule violation found during evaluation."""

    rule_id: str
    rule_title: str
    severity: str
    node_id: str
    node_name: str = ""
    posture_flag: str = ""
    remediation_hint: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "node_id": self.node_id,
            "node_name": self.node_name,
            "posture_flag": self.posture_flag,
            "remediation_hint": self.remediation_hint,
            "detected_at": self.detected_at.isoformat(),
        }


class PostureEvaluator:
    """
    Runs all CIS rules against the Neo4j graph for a given account.

    Usage:
        evaluator = PostureEvaluator(neo4j_client)
        findings = await evaluator.evaluate(account_id="123456789012")
    """

    def __init__(self, client: Neo4jClient, rules: list[CISRule] | None = None) -> None:
        self._client = client
        self._rules = rules if rules is not None else ALL_RULES

    async def evaluate(self, account_id: str | None = None) -> list[Finding]:
        """
        Run all CIS rules. For each violation, stamp the posture_flag on the node.
        Returns the full list of findings.
        """
        findings: list[Finding] = []
        tasks = [self._run_rule(rule, account_id) for rule in self._rules]
        raw = await asyncio.gather(*tasks, return_exceptions=True)

        for result in raw:
            if isinstance(result, BaseException):
                logger.error("Rule evaluation error: %s", result)
                continue
            findings.extend(r for r in result if isinstance(r, Finding))

        logger.info(
            "Posture evaluation complete: %d findings across %d rules",
            len(findings),
            len(self._rules),
        )
        return findings

    async def _run_rule(self, rule: CISRule, account_id: str | None) -> list[Finding]:
        """Execute a single rule's Cypher check and collect findings."""
        try:
            # Inject account_id filter if the query has $account_id param
            cypher = rule.cypher_check.strip()
            params: dict = {}
            if account_id and "$account_id" in cypher:
                params["account_id"] = account_id

            records = await self._client.query(cypher, params)
        except Exception as exc:
            logger.warning("Rule %s cypher failed: %s", rule.id, exc)
            return []

        findings = []
        for record in records:
            node_id = record.get("node_id", "")
            node_name = record.get("name") or record.get("db_id") or record.get("instance_id") or ""

            if not node_id:
                continue

            finding = Finding(
                rule_id=rule.id,
                rule_title=rule.title,
                severity=rule.severity,
                node_id=node_id,
                node_name=str(node_name),
                posture_flag=rule.posture_flag,
                remediation_hint=rule.remediation_hint,
            )
            findings.append(finding)

            # Stamp the posture_flag and severity on the node
            await self._stamp_node(node_id, rule.posture_flag, rule.severity)

        if findings:
            logger.info("Rule %s: %d violation(s)", rule.id, len(findings))

        return findings

    async def _stamp_node(self, node_id: str, posture_flag: str, severity: str) -> None:
        """Add posture_flag and severity to a node's posture_flags list (no duplicates)."""
        cypher = """
        MATCH (n {node_id: $node_id})
        SET n.posture_flags = [flag IN coalesce(n.posture_flags, []) WHERE flag <> $flag AND flag <> $severity]
            + [$flag, $severity]
        """
        try:
            await self._client.execute(
                cypher,
                {"node_id": node_id, "flag": posture_flag, "severity": severity},
            )
        except Exception as exc:
            logger.warning("Failed to stamp node %s with flag %s: %s", node_id, posture_flag, exc)

    async def get_findings_from_graph(
        self,
        account_id: str | None = None,
        severity: str | None = None,
        resource_type: str | None = None,
    ) -> list[dict]:
        """
        Query the graph for nodes that already have posture_flags stamped.
        Returns structured finding dicts (re-derives from flags, not re-runs rules).
        """
        conditions = ["size(n.posture_flags) > 0"]
        params: dict = {}

        if account_id:
            conditions.append("n.account_id = $account_id")
            params["account_id"] = account_id
        if severity:
            conditions.append("$severity IN n.posture_flags")
            params["severity"] = severity
        if resource_type:
            conditions.append("n.resource_type = $resource_type")
            params["resource_type"] = resource_type

        where_clause = "WHERE " + " AND ".join(conditions)
        cypher = f"""
        MATCH (n:GraphNode)
        {where_clause}
        RETURN n.node_id AS node_id, n.resource_type AS resource_type,
               n.posture_flags AS posture_flags, n.account_id AS account_id,
               n.region AS region
        ORDER BY n.discovered_at DESC
        """
        records = await self._client.query(cypher, params)

        results = []
        for r in records:
            flags = r.get("posture_flags", [])
            # Find the highest severity in the flags
            sev = "LOW"
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if s in flags:
                    sev = s
                    break
            results.append(
                {
                    "node_id": r["node_id"],
                    "resource_type": r.get("resource_type"),
                    "severity": sev,
                    "posture_flags": flags,
                    "account_id": r.get("account_id"),
                    "region": r.get("region"),
                }
            )
        return results
