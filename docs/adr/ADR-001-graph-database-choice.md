# ADR-001: Use Neo4j as the Graph Database

**Status:** Accepted
**Date:** 2026-02-25
**Deciders:** Baselyne Systems founding team

---

## Context

SENTINEL needs to model cloud infrastructure as a navigable graph and answer
questions like:
- "What is the attack path from the internet to this database?"
- "Which EC2 instances are reachable from this security group?"
- "What resources would be affected if this IAM role is compromised?"

These are fundamentally graph traversal problems. We evaluated three options:

1. **Relational DB (PostgreSQL with adjacency list)** — SQL-based graph traversal
   is verbose, slow for multi-hop queries, and requires recursive CTEs.

2. **Document DB (MongoDB)** — No native graph semantics; multi-hop traversal
   requires application-level recursion.

3. **Native graph DB (Neo4j)** — Designed for connected data; Cypher language
   is purpose-built for graph patterns; native index-free adjacency for O(1) hop.

---

## Decision

Use **Neo4j 5 Community Edition** as the graph database.

Deployment: Docker container via `docker-compose.yml` for local development.
Production: Neo4j AuraDB (managed) or self-hosted cluster.

---

## Rationale

- **Attack path queries** are 3-line Cypher vs. 30-line SQL
- **Cypher is readable**: the query language maps directly to how security engineers
  think about infrastructure relationships
- **Community Edition is free** for single-instance use — fits Phase 1 budget
- **APOC plugin** provides additional graph algorithms (centrality, path finding)
  that will be useful in Phase 2 reasoning
- **Mature Python driver** with async support (`neo4j` >= 5.x)

---

## Trade-offs accepted

| Trade-off | Mitigation |
|-----------|-----------|
| Neo4j requires Docker in dev | docker-compose.yml provided; single command |
| No ACID transactions for bulk writes | MERGE is idempotent; re-scans are safe |
| Community Edition has no clustering | Phase 2+: upgrade to Enterprise/AuraDB |
| Learning curve for Cypher | All queries are in `graph/queries.py` with examples |

---

## Consequences

- All graph interactions go through `Neo4jClient` (single abstraction layer)
- CIS rule checks are embedded as Cypher strings in `CISRule.cypher_check`
- Tests mock Neo4j at the `Neo4jClient` interface level (unit) or use
  testcontainers (E2E)
