"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { scanApi, type ScanJob } from "@/lib/api";

// ── Helpers ───────────────────────────────────────────────────────────────────

function statusColor(status: ScanJob["status"]) {
  switch (status) {
    case "completed":
      return "text-emerald-400";
    case "running":
      return "text-blue-400";
    case "failed":
      return "text-red-400";
    default:
      return "text-slate-400";
  }
}

function statusDot(status: ScanJob["status"]) {
  if (status === "running") {
    return (
      <span className="inline-block w-2 h-2 rounded-full bg-blue-400 animate-pulse mr-1.5" />
    );
  }
  const dotColor =
    status === "completed"
      ? "bg-emerald-400"
      : status === "failed"
      ? "bg-red-400"
      : "bg-slate-500";
  return <span className={`inline-block w-2 h-2 rounded-full ${dotColor} mr-1.5`} />;
}

function formatDuration(seconds: number) {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function elapsedSeconds(startedAt: string) {
  return (Date.now() - new Date(startedAt).getTime()) / 1000;
}

// ── Trigger button ────────────────────────────────────────────────────────────

function TriggerButton({ onTriggered }: { onTriggered: () => void }) {
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleClick() {
    setScanning(true);
    setError(null);
    try {
      await scanApi.trigger();
      onTriggered();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to trigger scan");
    } finally {
      setScanning(false);
    }
  }

  return (
    <div className="flex items-center gap-3">
      {error && <span className="text-xs text-red-400">{error}</span>}
      <button
        onClick={handleClick}
        disabled={scanning}
        className="px-4 py-2 text-sm rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
      >
        {scanning ? "Triggering…" : "New Scan"}
      </button>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ScansPage() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const hasActive = jobs.some((j) => j.status === "queued" || j.status === "running");

  const fetchJobs = useCallback(async () => {
    try {
      const data = await scanApi.listScans();
      setJobs(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load scans");
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load + polling when any job is active
  useEffect(() => {
    fetchJobs();
  }, [fetchJobs]);

  useEffect(() => {
    if (hasActive) {
      intervalRef.current = setInterval(fetchJobs, 3000);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [hasActive, fetchJobs]);

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Scan History</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            All AWS discovery scans — history persists across restarts
          </p>
        </div>
        <TriggerButton onTriggered={fetchJobs} />
      </div>

      {/* Error */}
      {error && (
        <div className="p-3 rounded bg-red-900/30 border border-red-700/40 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="rounded-xl border border-[#2a2d3e] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#2a2d3e] bg-[#1a1d2e]">
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                Started
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                Account
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                Regions
              </th>
              <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 uppercase tracking-wider">
                Nodes
              </th>
              <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 uppercase tracking-wider">
                Edges
              </th>
              <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 uppercase tracking-wider">
                Findings
              </th>
              <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 uppercase tracking-wider">
                Duration
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#2a2d3e]">
            {loading ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                  Loading…
                </td>
              </tr>
            ) : jobs.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                  No scans yet. Click &quot;New Scan&quot; to start one.
                </td>
              </tr>
            ) : (
              jobs.map((job) => {
                const duration =
                  job.result?.duration_seconds != null
                    ? formatDuration(job.result.duration_seconds)
                    : job.status === "running"
                    ? formatDuration(elapsedSeconds(job.started_at)) + " (running)"
                    : job.status === "failed"
                    ? "—"
                    : "…";

                return (
                  <tr key={job.job_id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="px-4 py-3">
                      <span className={`flex items-center font-medium ${statusColor(job.status)}`}>
                        {statusDot(job.status)}
                        {job.status.charAt(0).toUpperCase() + job.status.slice(1)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                      {formatDate(job.started_at)}
                    </td>
                    <td className="px-4 py-3 text-slate-300 font-mono text-xs">
                      {job.account_id}
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs">
                      {job.regions.join(", ")}
                    </td>
                    <td className="px-4 py-3 text-right text-slate-300 tabular-nums">
                      {job.result?.nodes_written ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-right text-slate-300 tabular-nums">
                      {job.result?.edges_written ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums">
                      {job.result != null ? (
                        <span
                          className={
                            job.result.findings_count > 0 ? "text-amber-400" : "text-emerald-400"
                          }
                        >
                          {job.result.findings_count}
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right text-slate-400 tabular-nums text-xs">
                      {duration}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Error details for failed jobs */}
      {jobs.some((j) => j.status === "failed" && j.error) && (
        <div className="flex flex-col gap-2">
          {jobs
            .filter((j) => j.status === "failed" && j.error)
            .map((j) => (
              <div
                key={j.job_id}
                className="p-3 rounded bg-red-900/20 border border-red-800/40 text-xs text-red-300 font-mono"
              >
                <span className="text-slate-500 mr-2">{formatDate(j.started_at)}</span>
                {j.error}
              </div>
            ))}
        </div>
      )}
    </div>
  );
}
