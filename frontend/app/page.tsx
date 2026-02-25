"use client";

import { useEffect, useState } from "react";
import { postureApi, scanApi, type PostureSummary, type ScanJob } from "@/lib/api";
import { FindingCard } from "@/components/posture/FindingCard";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-900/30 border-red-700",
  HIGH: "text-orange-400 bg-orange-900/30 border-orange-700",
  MEDIUM: "text-yellow-400 bg-yellow-900/30 border-yellow-700",
  LOW: "text-blue-400 bg-blue-900/30 border-blue-700",
};

function SummaryCard({
  severity,
  count,
}: {
  severity: string;
  count: number;
}) {
  return (
    <div
      className={`rounded-lg border p-5 ${SEVERITY_COLORS[severity] ?? "text-slate-400 bg-slate-800/30 border-slate-700"}`}
    >
      <p className="text-xs uppercase tracking-widest opacity-70">{severity}</p>
      <p className="text-4xl font-bold mt-2">{count}</p>
      <p className="text-xs mt-1 opacity-60">findings</p>
    </div>
  );
}

export default function DashboardPage() {
  const [summary, setSummary] = useState<PostureSummary | null>(null);
  const [scanning, setScanning] = useState(false);
  const [lastJob, setLastJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    postureApi
      .getSummary()
      .then(setSummary)
      .catch(() => setError("Could not connect to SENTINEL API. Is the backend running?"));
  }, []);

  const triggerScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const { job_id } = await scanApi.trigger({});
      // Poll for completion
      const poll = setInterval(async () => {
        const job = await scanApi.getStatus(job_id);
        setLastJob(job);
        if (job.status === "completed" || job.status === "failed") {
          clearInterval(poll);
          setScanning(false);
          // Refresh summary
          const newSummary = await postureApi.getSummary();
          setSummary(newSummary);
        }
      }, 2000);
    } catch (e) {
      setError(String(e));
      setScanning(false);
    }
  };

  return (
    <div className="p-8 max-w-5xl">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Posture Dashboard</h1>
          <p className="text-slate-500 text-sm mt-1">CIS AWS Foundations Benchmark v1.5</p>
        </div>
        <button
          onClick={triggerScan}
          disabled={scanning}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm rounded-md transition-colors"
        >
          {scanning ? "Scanning…" : "▶ Run Scan"}
        </button>
      </div>

      {error && (
        <div className="mb-6 p-4 rounded-lg bg-red-900/30 border border-red-700 text-red-300 text-sm">
          {error}
        </div>
      )}

      {lastJob && (
        <div className="mb-6 p-4 rounded-lg bg-slate-800/50 border border-slate-700 text-sm">
          <span className="text-slate-400">Last scan: </span>
          <span
            className={
              lastJob.status === "completed"
                ? "text-green-400"
                : lastJob.status === "failed"
                  ? "text-red-400"
                  : "text-yellow-400"
            }
          >
            {lastJob.status}
          </span>
          {lastJob.result && (
            <span className="text-slate-500 ml-3">
              {lastJob.result.nodes_written} nodes · {lastJob.result.edges_written} edges ·{" "}
              {lastJob.result.findings_count} findings · {lastJob.result.duration_seconds}s
            </span>
          )}
        </div>
      )}

      {/* Alignment Score */}
      {summary && (
        <div className="mb-8 p-6 rounded-xl bg-[#1a1d2e] border border-[#2a2d3e]">
          <p className="text-slate-400 text-sm mb-2">CIS Alignment Score</p>
          <div className="flex items-end gap-4">
            <span className="text-6xl font-bold text-slate-100">
              {summary.alignment_percentage}
              <span className="text-2xl text-slate-400">%</span>
            </span>
            <span className="text-slate-500 text-sm pb-2">
              across {summary.total_nodes} resources
            </span>
          </div>
          {/* Progress bar */}
          <div className="mt-4 h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-500 rounded-full transition-all"
              style={{ width: `${summary.alignment_percentage}%` }}
            />
          </div>
        </div>
      )}

      {/* Severity cards */}
      {summary && (
        <div className="grid grid-cols-4 gap-4 mb-8">
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => (
            <SummaryCard key={sev} severity={sev} count={summary.findings_by_severity[sev] ?? 0} />
          ))}
        </div>
      )}

      {/* No data state */}
      {summary && summary.total_nodes === 0 && (
        <div className="text-center py-16 text-slate-500">
          <p className="text-4xl mb-4">◈</p>
          <p className="text-lg">No resources discovered yet.</p>
          <p className="text-sm mt-2">Click "Run Scan" to discover your AWS environment.</p>
        </div>
      )}
    </div>
  );
}
