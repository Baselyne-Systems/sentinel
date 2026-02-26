"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { postureApi, scanApi, type PostureSummary, type ScanJob } from "@/lib/api";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-900/30 border-red-700",
  HIGH: "text-orange-400 bg-orange-900/30 border-orange-700",
  MEDIUM: "text-yellow-400 bg-yellow-900/30 border-yellow-700",
  LOW: "text-blue-400 bg-blue-900/30 border-blue-700",
};

// ── Scan stage labels ─────────────────────────────────────────────────────────

const STAGE_LABELS: Record<ScanJob["status"], string> = {
  queued: "Queued — waiting to start",
  running: "Running — discovering resources",
  completed: "Completed",
  failed: "Failed",
};

// ── Spinner ───────────────────────────────────────────────────────────────────

function Spinner() {
  return (
    <svg
      className="animate-spin h-4 w-4 text-blue-400"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}

// ── Progress stages indicator ─────────────────────────────────────────────────

function ScanProgressBar({ status }: { status: ScanJob["status"] }) {
  const stages: Array<{ key: ScanJob["status"]; label: string }> = [
    { key: "queued", label: "Queued" },
    { key: "running", label: "Running" },
    { key: "completed", label: "Done" },
  ];

  const activeIdx =
    status === "failed"
      ? 1 // show as stuck at running
      : stages.findIndex((s) => s.key === status);

  return (
    <div className="flex items-center gap-0 mt-2">
      {stages.map((stage, i) => {
        const isPast = i < activeIdx;
        const isActive = i === activeIdx && status !== "failed";
        const isFailed = status === "failed" && i === 1;

        return (
          <div key={stage.key} className="flex items-center">
            <div className="flex flex-col items-center gap-1">
              <div
                className={`w-2.5 h-2.5 rounded-full border-2 transition-colors ${
                  isFailed
                    ? "bg-red-500 border-red-500"
                    : isPast || (status === "completed" && i === 2)
                    ? "bg-blue-500 border-blue-500"
                    : isActive
                    ? "bg-blue-400 border-blue-400 animate-pulse"
                    : "bg-transparent border-slate-600"
                }`}
              />
              <span
                className={`text-[10px] ${
                  isFailed
                    ? "text-red-400"
                    : isActive || isPast || (status === "completed" && i === 2)
                    ? "text-slate-300"
                    : "text-slate-600"
                }`}
              >
                {stage.label}
              </span>
            </div>
            {i < stages.length - 1 && (
              <div
                className={`w-10 h-0.5 mb-3 mx-1 transition-colors ${
                  isPast || status === "completed" ? "bg-blue-500" : "bg-slate-700"
                }`}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Scan status banner ────────────────────────────────────────────────────────

function ScanBanner({ job }: { job: ScanJob }) {
  const isActive = job.status === "queued" || job.status === "running";

  return (
    <div
      className={`p-4 rounded-lg border text-sm ${
        job.status === "completed"
          ? "bg-emerald-900/20 border-emerald-700/40"
          : job.status === "failed"
          ? "bg-red-900/20 border-red-700/40"
          : "bg-blue-900/20 border-blue-700/40"
      }`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {isActive && <Spinner />}
          <span
            className={
              job.status === "completed"
                ? "text-emerald-400"
                : job.status === "failed"
                ? "text-red-400"
                : "text-blue-400"
            }
          >
            {STAGE_LABELS[job.status]}
          </span>
          {job.result && (
            <span className="text-slate-500 ml-2">
              {job.result.nodes_written} nodes · {job.result.edges_written} edges ·{" "}
              {job.result.findings_count} findings · {job.result.duration_seconds.toFixed(1)}s
            </span>
          )}
          {job.error && <span className="text-red-300 ml-2 font-mono text-xs">{job.error}</span>}
        </div>
        <Link href="/scans" className="text-xs text-slate-500 hover:text-slate-300 transition-colors">
          View all scans →
        </Link>
      </div>

      {isActive && <ScanProgressBar status={job.status} />}
    </div>
  );
}

// ── Summary card ──────────────────────────────────────────────────────────────

function SummaryCard({ severity, count }: { severity: string; count: number }) {
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

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [summary, setSummary] = useState<PostureSummary | null>(null);
  const [scanning, setScanning] = useState(false);
  const [lastJob, setLastJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    postureApi
      .getSummary()
      .then(setSummary)
      .catch(() => setError("Could not connect to SENTINEL API. Is the backend running?"));
  }, []);

  // Clean up poll on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const triggerScan = async () => {
    if (pollRef.current) clearInterval(pollRef.current);
    setScanning(true);
    setError(null);
    try {
      const { job_id } = await scanApi.trigger({});
      pollRef.current = setInterval(async () => {
        const job = await scanApi.getStatus(job_id);
        setLastJob(job);
        if (job.status === "completed" || job.status === "failed") {
          clearInterval(pollRef.current!);
          pollRef.current = null;
          setScanning(false);
          if (job.status === "completed") {
            const newSummary = await postureApi.getSummary();
            setSummary(newSummary);
          }
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
        <div className="flex items-center gap-3">
          <Link
            href="/scans"
            className="text-sm text-slate-400 hover:text-slate-200 transition-colors"
          >
            Scan history
          </Link>
          <button
            onClick={triggerScan}
            disabled={scanning}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm rounded-md transition-colors"
          >
            {scanning ? (
              <>
                <Spinner />
                Scanning…
              </>
            ) : (
              "▶ Run Scan"
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 rounded-lg bg-red-900/30 border border-red-700 text-red-300 text-sm">
          {error}
        </div>
      )}

      {lastJob && (
        <div className="mb-6">
          <ScanBanner job={lastJob} />
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
              className="h-full bg-blue-500 rounded-full transition-all duration-500"
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
          <p className="text-sm mt-2">Click &quot;Run Scan&quot; to discover your AWS environment.</p>
        </div>
      )}
    </div>
  );
}
