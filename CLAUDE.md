# SENTINEL — Project Context for Claude

## Executive Summary

SENTINEL is an autonomous cloud security architect agent that continuously observes, reasons about, and remediates security vulnerabilities in cloud infrastructure. It builds a live graph of the cloud environment, evaluates it against security benchmarks (CIS, NIST, SOC 2), and surfaces findings with actionable remediation guidance.

**Phase 1 Goal:** Prove SENTINEL can accurately model a real AWS cloud environment as a navigable graph with security posture annotations.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENTINEL                                  │
│                                                                   │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────────┐  │
│  │  Perception  │    │     Core     │    │       API          │  │
│  │   Engine     │───▶│  Graph + CIS │◀───│   FastAPI Layer    │  │
│  │  (boto3)     │    │   Knowledge  │    │                    │  │
│  └─────────────┘    └──────┬───────┘    └────────────────────┘  │
│                             │                       ▲             │
│                             ▼                       │             │
│                      ┌─────────────┐    ┌──────────┴─────────┐  │
│                      │    Neo4j    │    │      Frontend       │  │
│                      │   Graph DB  │    │  Next.js + Cytoscape│  │
│                      └─────────────┘    └────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Packages
| Package | Purpose |
|---------|---------|
| `sentinel-core` | Graph schema (Pydantic models), Neo4j client, CIS rules, posture evaluator |
| `sentinel-perception` | AWS connectors (boto3), graph builder, CloudTrail poller |
| `sentinel-api` | FastAPI REST API |
| Frontend | Next.js 14 + Cytoscape.js UI |

---

## Design Principles

1. **Graph-first:** Everything is a node or edge. Security analysis is graph traversal.
2. **Async throughout:** All I/O (AWS API calls, Neo4j writes) is async.
3. **Extensible connectors:** Each AWS service is a separate connector implementing a standard `discover()` interface.
4. **Typed rules:** CIS benchmark rules are Python dataclasses with embedded Cypher checks — no document DB needed.
5. **Cross-account ready:** All AWS connectors accept an `assume_role_arn` for multi-account support from day one.
6. **No hardcoded credentials:** All config via environment variables (pydantic-settings).

---

## Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Backend language | Python | 3.12+ |
| API framework | FastAPI | 0.115+ |
| AWS SDK | boto3 | latest |
| Graph DB | Neo4j Community | 5.x |
| Graph DB driver | neo4j (async) | 5.x |
| Data validation | Pydantic v2 | 2.x |
| Config | pydantic-settings | 2.x |
| Package manager | uv | latest |
| AWS mocking (tests) | moto | 5.x |
| Test runner | pytest + pytest-asyncio | latest |
| Frontend framework | Next.js | 14 (App Router) |
| Frontend language | TypeScript | 5.x |
| Graph visualization | Cytoscape.js | 3.x |
| Container | Docker + docker-compose | latest |

---

## Environment Variables

```bash
# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=sentinel_dev

# AWS
AWS_DEFAULT_REGION=us-east-1
AWS_REGIONS=us-east-1,us-west-2
AWS_ASSUME_ROLE_ARN=          # optional, for cross-account

# API
API_PORT=8000
ENABLE_RAW_CYPHER=false       # dev feature flag for POST /graph/query

# AI Agent
ANTHROPIC_API_KEY=
AGENT_PROVIDER=anthropic       # "anthropic" (default) or "openai"
# For OpenAI-compatible providers (Groq, Ollama, Together, vLLM):
# AGENT_PROVIDER=openai
# OPENAI_API_KEY=sk-...
# AGENT_BASE_URL=http://localhost:11434/v1
```

---

## Graph Schema Quick Reference

### Node Types
- `AWSAccount` → `Region` → all resources
- `EC2Instance`, `SecurityGroup`, `VPC`, `Subnet`
- `IAMRole`, `IAMUser`, `IAMPolicy`
- `S3Bucket`, `LambdaFunction`, `RDSInstance`

### Edge Types
- `HAS_RESOURCE`: Account→Region, Region→Resource
- `IN_VPC`: EC2/Lambda/RDS→VPC
- `IN_SUBNET`: EC2/RDS→Subnet
- `MEMBER_OF_SG`: EC2/Lambda/RDS→SecurityGroup
- `CAN_ASSUME`: Role/User→Role
- `HAS_ATTACHED_POLICY`: Role/User→Policy
- `EXECUTES_AS`: Lambda→Role
- `PEER_OF`: VPC→VPC

---

## Phase Roadmap

| Phase | Name | Goal |
|-------|------|------|
| 1 | Foundation | Live graph of AWS environment with CIS posture |
| 2 | Reasoning | LLM-powered analysis and remediation suggestions |
| 3 | Action | Autonomous remediation with human approval gates |
| 4 | Multi-cloud | GCP and Azure connectors |

---

## Development Commands

```bash
make dev      # Start Neo4j + API in watch mode
make scan     # Trigger a full AWS environment scan
make test     # Run pytest suite
make neo4j    # Start only Neo4j
make lint     # Run ruff + mypy
```

---

## Common Cypher Patterns

```cypher
// Find all public S3 buckets
MATCH (b:S3Bucket {is_public: true}) RETURN b

// Attack path: Internet → RDS
MATCH path = (sg:SecurityGroup)-[:MEMBER_OF_SG]-(r:RDSInstance {publicly_accessible: true})
WHERE any(rule IN sg.inbound_rules WHERE rule.cidr = '0.0.0.0/0')
RETURN path

// Nodes with critical findings
MATCH (n) WHERE 'CRITICAL' IN n.posture_flags RETURN n
```
