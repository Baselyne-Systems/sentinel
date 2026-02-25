"""
Prompts and message builders for the SENTINEL security agent.

This module owns all LLM-facing text: the system prompt that defines Claude's
persona and output contract, a graph schema reference injected into that
prompt, and two helper functions that build user-turn messages for the two
analysis modes (single finding, executive brief).

Prompt design principles
------------------------
1. **Graph-schema context first** — Claude needs to understand the node/edge
   vocabulary before it can write useful Cypher or interpret tool results.
2. **Explicit tool usage order** — the system prompt prescribes the sequence
   ``get_resource → get_neighbors → find_attack_paths → query_graph`` so
   Claude gathers context methodically rather than jumping straight to output.
3. **XML output contract** — a strict ``<analysis>…</analysis>`` tag structure
   is required for the final response.  ``agent.py`` parses this with regex;
   a fallback AnalysisResult is created if the block is missing so the stream
   always terminates cleanly.
4. **Production-quality IaC** — the prompt explicitly asks for production-ready
   Terraform, not pseudocode placeholders.

Constants
---------
``GRAPH_SCHEMA_CONTEXT``
    Short reference card for all node types, edge types, and posture flags.
    Embedded verbatim into ``SYSTEM_PROMPT``.

``SYSTEM_PROMPT``
    The full system turn sent to every ``client.messages.stream()`` call.
    Stateless — the conversation history and tool results live in ``messages``.

Functions
---------
``build_finding_message``
    Constructs the initial user-turn message for a single-finding analysis.
    Includes the resource metadata already known (type, account, region, flags)
    and instructs Claude to call the tools in order.

``build_brief_message``
    Constructs the initial user-turn message for a multi-finding brief.
    Lists the top-N findings by severity and asks Claude to prioritise,
    narrate, and recommend actions across all of them.
"""

from __future__ import annotations

# ── Graph schema reference (embedded into the system prompt) ──────────────────

GRAPH_SCHEMA_CONTEXT = """
## SENTINEL Graph Schema

### Node types
- AWSAccount, Region
- EC2Instance, SecurityGroup, VPC, Subnet
- IAMRole, IAMUser, IAMPolicy
- S3Bucket, LambdaFunction, RDSInstance

### Edge types
- HAS_RESOURCE: Account→Region, Region→Resource
- IN_VPC: EC2/Lambda/RDS→VPC
- IN_SUBNET: EC2/RDS→Subnet
- MEMBER_OF_SG: EC2/Lambda/RDS→SecurityGroup
- CAN_ASSUME: Role/User→Role
- HAS_ATTACHED_POLICY: Role/User→Policy
- EXECUTES_AS: Lambda→Role
- PEER_OF: VPC→VPC

### Posture flags (CIS AWS Benchmark v1.5)
Severity levels: CRITICAL, HIGH, MEDIUM, LOW

Common flags:
- SG_OPEN_SSH, SG_OPEN_RDP, SG_OPEN_ALL_INGRESS (SecurityGroup)
- S3_PUBLIC_ACL, S3_NO_VERSIONING, S3_NO_ENCRYPTION (S3Bucket)
- IAM_STAR_POLICY, IAM_NO_MFA_CONSOLE (IAMUser/IAMPolicy)
- RDS_PUBLIC, RDS_NO_ENCRYPTION, RDS_NO_BACKUP (RDSInstance)
- LAMBDA_STAR_ROLE (LambdaFunction)
"""

# ── System prompt ──────────────────────────────────────────────────────────────

#: Sent as the ``system`` parameter on every ``client.messages.stream()`` call.
#: Defines Claude's role, available tools, expected reasoning process, and the
#: mandatory XML output structure that ``_parse_analysis_xml()`` will parse.
SYSTEM_PROMPT = f"""You are SENTINEL, an autonomous cloud security architect AI.
Your job is to analyze AWS security findings from a live infrastructure graph,
assess real-world risk, and provide actionable remediation guidance.

{GRAPH_SCHEMA_CONTEXT}

## Your capabilities
You have access to 4 graph query tools:
1. `get_resource(node_id)` — fetch full details of any resource node
2. `get_neighbors(node_id, depth)` — explore connected resources (blast radius)
3. `find_attack_paths(node_id)` — identify exploitable attack vectors
4. `query_graph(cypher, params)` — run custom read-only Cypher queries

## Analysis process
1. First call `get_resource` to understand the flagged resource fully
2. Call `get_neighbors` to assess blast radius (what's connected)
3. Call `find_attack_paths` to identify exploitability vectors
4. Use `query_graph` if you need additional context not covered above
5. Synthesize your findings into a structured analysis

## Output format (REQUIRED)
After gathering context through tool use, produce your final analysis wrapped in XML:

```xml
<analysis>
  <risk_narrative>
    2-4 paragraphs describing: what the finding is, why it matters in context,
    what an attacker could do, and the business impact.
  </risk_narrative>
  <priority_score>N</priority_score>
  <priority_rationale>
    1-2 sentences explaining why you chose this score (1=informational, 10=critical/actively exploitable).
  </priority_rationale>
  <remediation_steps>
    <step number="1">
      <title>Short action title</title>
      <description>Detailed explanation of what to do and why.</description>
      <iac_snippet>```hcl
# Terraform snippet if applicable
```</iac_snippet>
    </step>
    <!-- 2-5 steps total -->
  </remediation_steps>
  <attack_paths_summary>
    Brief summary of the most concerning attack paths found, or "No critical attack paths identified."
  </attack_paths_summary>
</analysis>
```

Be specific, actionable, and accurate. Reference actual node IDs and resource names
from your tool queries. Terraform snippets should be production-ready.
"""


# ── Message builders ───────────────────────────────────────────────────────────


def build_finding_message(
    node_id: str,
    resource_type: str,
    posture_flags: list[str],
    account_id: str,
    region: str,
    additional_context: str = "",
) -> str:
    """
    Build the initial user-turn message for a single-finding analysis.

    This message seeds the conversation with the metadata SENTINEL already
    knows (from the graph and the posture evaluator) before Claude starts
    calling tools to gather further context.  Providing this upfront avoids
    a redundant ``get_resource`` call solely to learn the resource type or
    account ID — though Claude will still call ``get_resource`` to fetch
    the full property set.

    Args:
        node_id: Unique graph node identifier for the flagged resource.
        resource_type: Human-readable type string (e.g. ``"S3Bucket"``).
        posture_flags: List of CIS posture flag strings already stamped on
            this node (e.g. ``["CRITICAL", "S3_PUBLIC_ACL", "S3_NO_VERSIONING"]``).
        account_id: AWS account ID that owns this resource.
        region: AWS region where the resource lives (e.g. ``"us-east-1"``).
        additional_context: Optional free-text string injected at the end of
            the message.  Use this to pass caller-supplied hints (e.g. "this
            bucket stores PCI cardholder data").

    Returns:
        Formatted markdown string ready to use as the ``content`` of the first
        ``{"role": "user"}`` message in the conversation.
    """
    flags_str = ", ".join(posture_flags) if posture_flags else "none"
    msg = f"""Analyze the following security finding from the SENTINEL graph:

**Resource:** `{node_id}`
**Type:** {resource_type}
**Account:** {account_id}
**Region:** {region}
**Posture flags:** {flags_str}

Please:
1. Use `get_resource` to fetch the full configuration of this resource
2. Use `get_neighbors` to understand what other resources are connected
3. Use `find_attack_paths` to identify exploitable attack vectors
4. Provide your structured analysis in the required XML format
"""
    if additional_context:
        msg += f"\n**Additional context:** {additional_context}\n"
    return msg


def build_brief_message(
    findings: list[dict],
    account_id: str,
) -> str:
    """
    Build the initial user-turn message for a multi-finding executive brief.

    Presents the top-N findings (pre-sorted by severity rank) and instructs
    Claude to cross-reference them, identify the highest-risk items, and
    produce a consolidated narrative with top-level remediation priorities.

    Args:
        findings: List of finding dicts, each with at least ``node_id``,
            ``resource_type``, and ``posture_flags`` keys.  Should already be
            sorted by descending severity rank (CRITICAL first) by the caller.
        account_id: AWS account ID whose posture is being summarised.

    Returns:
        Formatted string ready to use as the ``content`` of the first
        ``{"role": "user"}`` message in the brief conversation.
    """
    lines = [
        f"Generate an executive security brief for AWS account `{account_id}`.",
        "",
        f"Top {len(findings)} findings by severity:",
        "",
    ]
    for i, f in enumerate(findings, 1):
        flags = ", ".join(f.get("posture_flags", []))
        lines.append(
            f"{i}. `{f.get('node_id', 'unknown')}` ({f.get('resource_type', '?')}) "
            f"— flags: {flags}"
        )

    lines += [
        "",
        "For each finding, briefly assess the risk and prioritize them.",
        "Then provide an overall risk narrative and top 3 recommended actions.",
        "Use the graph tools to gather context on the most critical findings.",
        "Wrap your output in the standard <analysis> XML format.",
    ]
    return "\n".join(lines)
