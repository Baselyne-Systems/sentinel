"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { graphApi, agentApi, type GraphNode, type AnalysisResult } from "@/lib/api";
import { AnalysisPanel } from "@/components/agent/AnalysisPanel";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-900/40 text-red-300 border-red-700",
  HIGH: "bg-orange-900/40 text-orange-300 border-orange-700",
  MEDIUM: "bg-amber-900/40 text-amber-300 border-amber-700",
  LOW: "bg-slate-700/40 text-slate-300 border-slate-600",
};

function Flag({ flag }: { flag: string }) {
  const severity = flag === "CRITICAL" || flag === "HIGH" || flag === "MEDIUM" || flag === "LOW"
    ? flag
    : flag.startsWith("SG_OPEN") || flag === "S3_PUBLIC_ACL" || flag === "RDS_PUBLIC"
      ? "CRITICAL"
      : "MEDIUM";
  const color = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.MEDIUM;
  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-mono ${color}`}>
      {flag}
    </span>
  );
}

function ResourceProperty({ label, value }: { label: string; value: unknown }) {
  if (value === null || value === undefined || value === "") return null;
  const displayValue = Array.isArray(value)
    ? value.join(", ") || "—"
    : typeof value === "boolean"
      ? value ? "Yes" : "No"
      : String(value);
  return (
    <div className="flex gap-2 text-sm">
      <span className="text-slate-500 shrink-0 w-40">{label}</span>
      <span className="text-slate-300 font-mono break-all">{displayValue}</span>
    </div>
  );
}

const SKIP_PROPS = new Set(["posture_flags", "agent_analysis", "tags"]);

export default function FindingDetailPage() {
  const params = useParams();
  const router = useRouter();
  const nodeId = decodeURIComponent(params.id as string);

  const [node, setNode] = useState<GraphNode | null>(null);
  const [cachedAnalysis, setCachedAnalysis] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    Promise.all([
      graphApi.getNode(nodeId),
      agentApi.getAnalysis(nodeId).catch(() => null),
    ])
      .then(([nodeData, analysis]) => {
        setNode(nodeData);
        setCachedAnalysis(analysis);
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, [nodeId]);

  if (loading) {
    return (
      <div className="p-8 text-slate-500 text-sm">Loading finding…</div>
    );
  }

  if (error || !node) {
    return (
      <div className="p-8">
        <p className="text-red-400 text-sm">{error || "Finding not found."}</p>
        <button
          onClick={() => router.back()}
          className="mt-4 text-sm text-slate-500 hover:text-slate-300 underline"
        >
          ← Back to findings
        </button>
      </div>
    );
  }

  const postureFlags: string[] = (node.posture_flags as string[]) || [];
  const tags = (node.tags as Record<string, string>) || {};

  return (
    <div className="p-8 max-w-4xl">
      {/* Back nav */}
      <button
        onClick={() => router.back()}
        className="text-sm text-slate-500 hover:text-slate-300 mb-6 flex items-center gap-1"
      >
        ← Findings
      </button>

      {/* Header */}
      <div className="mb-6">
        <div className="flex items-start gap-3 flex-wrap">
          <h1 className="text-2xl font-bold text-slate-100 break-all">{nodeId}</h1>
        </div>
        <div className="flex items-center gap-2 mt-2 flex-wrap">
          <span className="text-slate-500 text-sm">{node.resource_type}</span>
          <span className="text-slate-600">·</span>
          <span className="text-slate-500 text-sm">{node.region}</span>
          <span className="text-slate-600">·</span>
          <span className="text-slate-500 text-sm font-mono">{node.account_id}</span>
        </div>

        {/* Posture flags */}
        {postureFlags.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-3">
            {postureFlags.map((f) => (
              <Flag key={f} flag={f} />
            ))}
          </div>
        )}
      </div>

      {/* Resource properties */}
      <div className="bg-[#13152a] border border-[#2a2d3e] rounded-xl p-6 mb-6">
        <h2 className="text-slate-300 font-medium text-sm uppercase tracking-wider mb-4">
          Resource Properties
        </h2>
        <div className="space-y-2">
          {Object.entries(node)
            .filter(([k]) => !SKIP_PROPS.has(k))
            .map(([k, v]) => (
              <ResourceProperty key={k} label={k} value={v} />
            ))}
        </div>

        {/* Tags */}
        {Object.keys(tags).length > 0 && (
          <div className="mt-4 pt-4 border-t border-[#2a2d3e]">
            <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Tags</p>
            <div className="flex flex-wrap gap-2">
              {Object.entries(tags).map(([k, v]) => (
                <span
                  key={k}
                  className="bg-[#1a1d2e] border border-[#2a2d3e] text-slate-400 text-xs px-2 py-0.5 rounded font-mono"
                >
                  {k}={v}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* AI Analysis */}
      <AnalysisPanel nodeId={nodeId} initialAnalysis={cachedAnalysis} />
    </div>
  );
}
