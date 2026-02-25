# SENTINEL Architecture

## System overview

SENTINEL is a graph-based cloud security posture management (CSPM) system.
The central insight: **security analysis is graph traversal**. Attack paths,
privilege escalation chains, blast radius, and compliance violations are all
expressible as Cypher queries over a property graph.

```
AWS Account
    │
    ▼ HAS_RESOURCE
  Region ──────────────────────────────────────────────┐
    │ HAS_RESOURCE                                       │
    ├──── EC2Instance ──MEMBER_OF_SG──▶ SecurityGroup   │
    │         │                                          │
    │         └──IN_VPC──▶ VPC ◀──IN_VPC── RDSInstance  │
    │                       │                            │
    │                       └──IN_VPC── LambdaFunction   │
    │                                        │           │
    ├──── IAMRole ◀──EXECUTES_AS─────────────┘          │
    │         │                                          │
    │         └──HAS_ATTACHED_POLICY──▶ IAMPolicy        │
    │                                                     │
    └──── S3Bucket ───────────────────────────────────────┘
```

## Data flow

```
┌─────────────┐    boto3      ┌─────────────────┐
│  AWS APIs   │ ──────────── ▶│  AWS Connectors  │
└─────────────┘               │  (async, moto-  │
                               │   mockable)     │
                               └────────┬────────┘
                                        │ list[GraphNode], list[GraphEdge]
                                        ▼
                               ┌─────────────────┐
                               │  GraphBuilder   │  orchestration + edge resolution
                               └────────┬────────┘
                                        │ upsert_node / upsert_edge
                                        ▼
                               ┌─────────────────┐
                               │     Neo4j        │  property graph
                               │   (Docker)       │
                               └────────┬────────┘
                                        │ Cypher checks
                                        ▼
                               ┌─────────────────┐
                               │PostureEvaluator │  stamps posture_flags
                               │  (CIS rules)    │
                               └────────┬────────┘
                                        │
                                        ▼
                               ┌─────────────────┐     ┌──────────────────┐
                               │  FastAPI API     │◀────│  Next.js frontend│
                               │  /api/v1/...     │────▶│  Cytoscape.js    │
                               └─────────────────┘     └──────────────────┘
```

## Key design decisions

See the ADR directory for full context. Summary:

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Graph DB | Neo4j 5 Community | Native graph traversal for attack paths |
| Schema | Pydantic v2 models | Type safety + OpenAPI generation |
| Async | asyncio + to_thread | boto3 is sync; we wrap it |
| CIS rules | Python dataclasses | Type-checked, no external DB needed |
| AWS mocking | moto | Full AWS API simulation for fast tests |
| E2E DB | testcontainers | Real Neo4j for E2E tests, no cloud dependency |

## Neo4j schema

### Node labels

Every node has two labels:
- `GraphNode` — universal base label (used for cross-type queries)
- A type-specific label, e.g. `S3Bucket`, `EC2Instance` (used for typed queries)

### Key indexes

```cypher
CREATE INDEX node_id_idx FOR (n:GraphNode) ON (n.node_id)
CREATE INDEX account_id_idx FOR (n:GraphNode) ON (n.account_id)
CREATE INDEX resource_type_idx FOR (n:GraphNode) ON (n.resource_type)
CREATE INDEX posture_flags_idx FOR (n:GraphNode) ON (n.posture_flags)
```

### Posture flags storage

`posture_flags` is a string array property on every node. It contains both
severity labels (for fast filtering) and specific flag names:

```
["CRITICAL", "SG_OPEN_SSH", "HIGH", "SG_OPEN_RDP"]
```

This denormalized approach avoids joins and makes the common query
`MATCH (n) WHERE 'CRITICAL' IN n.posture_flags` a simple index scan.

## Connector interface

Every connector exposes exactly one function:

```python
async def discover(
    session: boto3.Session,
    account_id: str,
    region: str,
) -> tuple[list[GraphNode], list[GraphEdge]]:
```

This uniformity means `GraphBuilder` can call them all the same way and
aggregate results without knowing the internals of each connector.

## CloudTrail poller (Phase 1)

The poller runs every 60 seconds and calls `CloudTrail.lookup_events` with
`ReadOnly=false` to find mutation events. When a mutation event is detected
(e.g. `AuthorizeSecurityGroupIngress`), it triggers a targeted re-scan of
just the affected resource type — avoiding a full account re-scan.

Phase 2 upgrade path: replace polling with a Kinesis/SQS event stream from
CloudTrail for near-real-time updates.

## Phase roadmap

| Phase | Addition | Design impact |
|-------|----------|---------------|
| 2 | Claude LLM reasoning | New `sentinel-reasoning` package; Anthropic SDK |
| 2 | Remediation suggestions | New edge type: `REMEDIATES`; findings get `suggestion` property |
| 3 | Autonomous remediation | New router `/remediation`; approval gates via webhook |
| 4 | GCP + Azure | New connectors; CloudProvider enum already has GCP/AZURE values |
