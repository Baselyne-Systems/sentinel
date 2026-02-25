/**
 * Typed API client for SENTINEL backend.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const API_V1 = `${API_BASE}/api/v1`;

// ── Types ─────────────────────────────────────────────────────────────────────

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface GraphNode {
  node_id: string;
  resource_type: string;
  account_id: string;
  region: string;
  posture_flags: string[];
  tags: Record<string, string>;
  discovered_at: string;
  // Type-specific fields
  name?: string;
  instance_id?: string;
  group_id?: string;
  vpc_id?: string;
  db_id?: string;
  function_name?: string;
  arn?: string;
  is_public?: boolean;
  publicly_accessible?: boolean;
  has_mfa?: boolean;
  [key: string]: unknown;
}

export interface GraphEdge {
  from: string;
  to: string;
  type: string;
}

export interface SubgraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  root_node_id: string;
}

export interface Finding {
  node_id: string;
  resource_type: string;
  severity: Severity;
  posture_flags: string[];
  account_id: string;
  region: string;
}

export interface PostureSummary {
  total_nodes: number;
  findings_by_severity: Record<Severity, number>;
  alignment_percentage: number;
  account_id: string | null;
}

export interface CISRule {
  id: string;
  title: string;
  severity: Severity;
  resource_types: string[];
  posture_flag: string;
  remediation_hint: string;
  tags: string[];
}

export interface ScanJob {
  job_id: string;
  status: "queued" | "running" | "completed" | "failed";
  account_id: string;
  regions: string[];
  started_at: string;
  completed_at: string | null;
  result: ScanResult | null;
  error: string | null;
}

export interface ScanResult {
  nodes_written: number;
  edges_written: number;
  findings_count: number;
  duration_seconds: number;
  errors: string[];
}

export interface Account {
  account_id: string;
  name: string;
  assume_role_arn: string;
  regions: string[];
  registered_at: string;
}

// ── Fetch helper ──────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_V1}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${path} → ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ── Graph endpoints ───────────────────────────────────────────────────────────

export const graphApi = {
  listNodes: (params?: {
    type?: string;
    account_id?: string;
    region?: string;
    limit?: number;
    offset?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.type) qs.set("type", params.type);
    if (params?.account_id) qs.set("account_id", params.account_id);
    if (params?.region) qs.set("region", params.region);
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.offset) qs.set("offset", String(params.offset));
    const query = qs.toString();
    return apiFetch<GraphNode[]>(`/graph/nodes${query ? `?${query}` : ""}`);
  },

  getNode: (nodeId: string) =>
    apiFetch<GraphNode & { edges: unknown[] }>(`/graph/nodes/${encodeURIComponent(nodeId)}`),

  getNeighbors: (nodeId: string, depth = 2) =>
    apiFetch<SubgraphResponse>(
      `/graph/nodes/${encodeURIComponent(nodeId)}/neighbors?depth=${depth}`
    ),

  rawQuery: (cypher: string, params?: Record<string, unknown>) =>
    apiFetch<unknown[]>("/graph/query", {
      method: "POST",
      body: JSON.stringify({ cypher, params: params ?? {} }),
    }),
};

// ── Posture endpoints ─────────────────────────────────────────────────────────

export const postureApi = {
  getFindings: (params?: {
    severity?: Severity;
    resource_type?: string;
    account_id?: string;
  }) => {
    const qs = new URLSearchParams();
    if (params?.severity) qs.set("severity", params.severity);
    if (params?.resource_type) qs.set("resource_type", params.resource_type);
    if (params?.account_id) qs.set("account_id", params.account_id);
    const query = qs.toString();
    return apiFetch<Finding[]>(`/posture/findings${query ? `?${query}` : ""}`);
  },

  getSummary: (accountId?: string) => {
    const qs = accountId ? `?account_id=${accountId}` : "";
    return apiFetch<PostureSummary>(`/posture/summary${qs}`);
  },

  getRules: () => apiFetch<CISRule[]>("/posture/rules"),
};

// ── Scan endpoints ────────────────────────────────────────────────────────────

export const scanApi = {
  trigger: (body?: {
    account_id?: string;
    regions?: string[];
    assume_role_arn?: string;
    clear_first?: boolean;
  }) =>
    apiFetch<{ job_id: string; status: string; account_id: string }>("/scan/trigger", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),

  getStatus: (jobId: string) =>
    apiFetch<ScanJob>(`/scan/${encodeURIComponent(jobId)}/status`),

  listScans: () => apiFetch<ScanJob[]>("/scan/"),
};

// ── Agent types ───────────────────────────────────────────────────────────────

export interface RemediationStep {
  step_number: number;
  title: string;
  description: string;
  iac_snippet: string;
}

export interface AnalysisResult {
  node_id: string;
  risk_narrative: string;
  priority_score: number;
  priority_rationale: string;
  remediation_steps: RemediationStep[];
  attack_paths_summary: string;
  model: string;
  analyzed_at: string;
}

export type SSEEventType =
  | { event: "text_delta"; text: string }
  | { event: "tool_use"; tool_name: string; tool_input: Record<string, unknown>; tool_result_summary: string }
  | { event: "analysis_complete"; result: AnalysisResult }
  | { event: "error"; message: string };

// ── Agent endpoints ───────────────────────────────────────────────────────────

export const agentApi = {
  /**
   * Stream an AI analysis for a finding node via SSE.
   * onEvent is called for each parsed SSE event.
   * Returns an AbortController so the caller can cancel the stream.
   */
  streamAnalysis(
    nodeId: string,
    onEvent: (event: SSEEventType) => void,
    onDone?: () => void,
    onError?: (err: Error) => void
  ): AbortController {
    const controller = new AbortController();
    const url = `${API_V1}/agent/findings/${encodeURIComponent(nodeId)}/analyze`;

    fetch(url, { method: "POST", signal: controller.signal })
      .then(async (res) => {
        if (!res.ok) {
          const text = await res.text();
          throw new Error(`Agent API ${res.status}: ${text}`);
        }
        const reader = res.body?.getReader();
        if (!reader) throw new Error("No response body");

        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          const lines = buffer.split("\n\n");
          buffer = lines.pop() ?? "";

          for (const chunk of lines) {
            const dataLine = chunk.trim();
            if (!dataLine.startsWith("data:")) continue;
            const raw = dataLine.slice(5).trim();
            if (raw === "[DONE]") {
              onDone?.();
              return;
            }
            try {
              const parsed = JSON.parse(raw) as SSEEventType;
              onEvent(parsed);
            } catch {
              // ignore malformed lines
            }
          }
        }
        onDone?.();
      })
      .catch((err: Error) => {
        if (err.name !== "AbortError") {
          onError?.(err);
        }
      });

    return controller;
  },

  /** Fetch a cached AnalysisResult (404 if not yet analyzed). */
  getAnalysis: (nodeId: string): Promise<AnalysisResult> =>
    apiFetch<AnalysisResult>(`/agent/findings/${encodeURIComponent(nodeId)}/analysis`),
};

// ── Account endpoints ─────────────────────────────────────────────────────────

export const accountsApi = {
  register: (body: {
    account_id: string;
    name?: string;
    assume_role_arn?: string;
    regions?: string[];
  }) =>
    apiFetch<Account>("/accounts", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  list: () => apiFetch<Account[]>("/accounts"),

  get: (accountId: string) =>
    apiFetch<Account>(`/accounts/${encodeURIComponent(accountId)}`),
};
