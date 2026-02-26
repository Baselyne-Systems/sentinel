"""Canned Cypher queries for common SENTINEL security analyses."""

from __future__ import annotations

from typing import Any

from sentinel_core.graph.client import Neo4jClient


class GraphQueries:
    """
    Pre-built Cypher queries for security graph analysis.
    All methods return list[dict] from Neo4j.
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    # ── Security queries ──────────────────────────────────────────────────────

    async def find_public_s3_buckets(self, account_id: str | None = None) -> list[dict[str, Any]]:
        """Return all S3Bucket nodes marked as public."""
        if account_id:
            cypher = """
            MATCH (b:S3Bucket {is_public: true, account_id: $account_id})
            RETURN b
            """
            return await self._client.query(cypher, {"account_id": account_id})
        cypher = "MATCH (b:S3Bucket {is_public: true}) RETURN b"
        return await self._client.query(cypher)

    async def find_overly_permissive_sgs(
        self, account_id: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Return SecurityGroups that have any inbound rule with cidr 0.0.0.0/0 or ::/0.
        Stored as serialized list in inbound_rules property.
        """
        params: dict[str, Any] = {}
        account_filter = "AND sg.account_id = $account_id" if account_id else ""
        if account_id:
            params["account_id"] = account_id
        cypher = f"""
        MATCH (sg:SecurityGroup)
        WHERE (
            any(flag IN sg.posture_flags WHERE flag IN ['SG_OPEN_SSH', 'SG_OPEN_RDP', 'SG_OPEN_ALL_INGRESS'])
        ) {account_filter}
        RETURN sg
        """
        return await self._client.query(cypher, params)

    async def find_roles_with_star_actions(
        self, account_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Return IAMPolicy nodes that grant Action: '*'."""
        params: dict[str, Any] = {}
        account_filter = "AND p.account_id = $account_id" if account_id else ""
        if account_id:
            params["account_id"] = account_id
        cypher = f"""
        MATCH (p:IAMPolicy)
        WHERE 'IAM_STAR_POLICY' IN p.posture_flags {account_filter}
        RETURN p
        """
        return await self._client.query(cypher, params)

    async def find_internet_to_rds_paths(
        self, account_id: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Find attack paths: SecurityGroup with open ingress → RDS instance that is publicly accessible.
        """
        params: dict[str, Any] = {}
        account_filter = "AND rds.account_id = $account_id" if account_id else ""
        if account_id:
            params["account_id"] = account_id
        cypher = f"""
        MATCH (rds:RDSInstance {{publicly_accessible: true}})-[:MEMBER_OF_SG]->(sg:SecurityGroup)
        WHERE any(flag IN sg.posture_flags WHERE flag IN ['SG_OPEN_ALL_INGRESS', 'SG_OPEN_SSH'])
        {account_filter}
        RETURN rds, sg
        """
        return await self._client.query(cypher, params)

    async def find_iam_users_without_mfa(
        self, account_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Return IAMUser nodes that have console access but no MFA."""
        params: dict[str, Any] = {}
        account_filter = "WHERE u.account_id = $account_id" if account_id else ""
        if account_id:
            params["account_id"] = account_id
        cypher = f"""
        MATCH (u:IAMUser {{has_mfa: false, has_console_access: true}})
        {account_filter}
        RETURN u
        """
        return await self._client.query(cypher, params)

    async def find_unencrypted_rds(self, account_id: str | None = None) -> list[dict[str, Any]]:
        """Return RDS instances without encryption."""
        params: dict[str, Any] = {}
        account_filter = "WHERE r.account_id = $account_id" if account_id else ""
        if account_id:
            params["account_id"] = account_id
        cypher = f"""
        MATCH (r:RDSInstance {{encrypted: false}})
        {account_filter}
        RETURN r
        """
        return await self._client.query(cypher, params)

    # ── Navigation queries ────────────────────────────────────────────────────

    async def get_resource_by_id(self, resource_id: str) -> dict[str, Any] | None:
        """Fetch a single node by node_id."""
        cypher = "MATCH (n {node_id: $node_id}) RETURN n LIMIT 1"
        results = await self._client.query(cypher, {"node_id": resource_id})
        return results[0] if results else None

    async def get_neighbors(
        self,
        resource_id: str,
        depth: int = 2,
    ) -> list[dict[str, Any]]:
        """Return all nodes and edges within `depth` hops of the given node."""
        cypher = f"""
        MATCH path = (start {{node_id: $node_id}})-[*1..{depth}]-(neighbor)
        RETURN nodes(path) AS nodes, relationships(path) AS rels
        """
        return await self._client.query(cypher, {"node_id": resource_id})

    async def list_nodes(
        self,
        resource_type: str | None = None,
        account_id: str | None = None,
        region: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Paginated node listing with optional filters."""
        conditions = []
        params: dict[str, Any] = {"limit": limit, "skip": offset}
        if resource_type:
            conditions.append("n.resource_type = $resource_type")
            params["resource_type"] = resource_type
        if account_id:
            conditions.append("n.account_id = $account_id")
            params["account_id"] = account_id
        if region:
            conditions.append("n.region = $region")
            params["region"] = region

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        cypher = f"""
        MATCH (n:GraphNode)
        {where_clause}
        RETURN n
        ORDER BY n.discovered_at DESC
        SKIP $skip
        LIMIT $limit
        """
        return await self._client.query(cypher, params)

    async def get_posture_summary(self, account_id: str | None = None) -> dict[str, Any]:
        """Return counts of nodes with each severity posture flag."""
        account_filter = "WHERE n.account_id = $account_id" if account_id else ""
        params: dict[str, Any] = {}
        if account_id:
            params["account_id"] = account_id
        cypher = f"""
        MATCH (n:GraphNode)
        {account_filter}
        WITH n,
            CASE WHEN 'CRITICAL' IN n.posture_flags THEN 1 ELSE 0 END AS has_critical,
            CASE WHEN 'HIGH' IN n.posture_flags THEN 1 ELSE 0 END AS has_high,
            CASE WHEN 'MEDIUM' IN n.posture_flags THEN 1 ELSE 0 END AS has_medium,
            CASE WHEN 'LOW' IN n.posture_flags THEN 1 ELSE 0 END AS has_low
        RETURN
            count(n) AS total_nodes,
            sum(has_critical) AS critical_count,
            sum(has_high) AS high_count,
            sum(has_medium) AS medium_count,
            sum(has_low) AS low_count
        """
        results = await self._client.query(cypher, params)
        return results[0] if results else {}
