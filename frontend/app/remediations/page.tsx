"use client";

import { useEffect, useState, useCallback } from "react";
import { remediationApi, type RemediationJob, type JobStatus } from "@/lib/api";
import { RemediationProposalCard } from "@/components/remediation/RemediationProposalCard";
import { ApprovalModal } from "@/components/remediation/ApprovalModal";

type FilterTab = "all" | "pending" | "approved" | "executing" | "completed" | "rejected" | "failed";

const TABS: { key: FilterTab; label: string }[] = [
  { key: "all", label: "All" },
  { key: "pending", label: "Pending" },
  { key: "approved", label: "Approved" },
  { key: "executing", label: "Executing" },
  { key: "completed", label: "Completed" },
  { key: "rejected", label: "Rejected" },
  { key: "failed", label: "Failed" },
];

type ModalState = {
  job: RemediationJob;
  mode: "approve" | "reject";
} | null;

export default function RemediationsPage() {
  const [jobs, setJobs] = useState<RemediationJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<FilterTab>("all");
  const [modal, setModal] = useState<ModalState>(null);
  const [modalLoading, setModalLoading] = useState(false);
  const [error, setError] = useState("");

  const loadJobs = useCallback(async () => {
    try {
      const data = await remediationApi.list();
      setJobs(data);
    } catch (err: unknown) {
      if (err instanceof Error) setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadJobs();
    // Poll every 3 seconds while any job is executing or approved
    const interval = setInterval(() => {
      const hasActive = jobs.some(
        (j) => j.status === "executing" || j.status === "approved"
      );
      if (hasActive) loadJobs();
    }, 3000);
    return () => clearInterval(interval);
  }, [loadJobs, jobs]);

  const filtered = tab === "all" ? jobs : jobs.filter((j) => j.status === tab);

  const countForTab = (t: FilterTab) =>
    t === "all" ? jobs.length : jobs.filter((j) => j.status === t).length;

  function openModal(jobId: string, mode: "approve" | "reject") {
    const job = jobs.find((j) => j.job_id === jobId);
    if (job) setModal({ job, mode });
  }

  async function handleConfirm() {
    if (!modal) return;
    setModalLoading(true);
    try {
      let updated: RemediationJob;
      if (modal.mode === "approve") {
        updated = await remediationApi.approve(modal.job.job_id);
      } else {
        updated = await remediationApi.reject(modal.job.job_id);
      }
      setJobs((prev) =>
        prev.map((j) => (j.job_id === updated.job_id ? updated : j))
      );
      setModal(null);
    } catch (err: unknown) {
      if (err instanceof Error) setError(err.message);
    } finally {
      setModalLoading(false);
    }
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-100">Remediations</h1>
        <p className="text-slate-500 text-sm mt-1">
          Phase 3 — autonomous AWS remediation with human approval gates
        </p>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 bg-red-950/40 border border-red-900/50 text-red-400 text-sm px-4 py-3 rounded-lg">
          {error}
          <button
            onClick={() => setError("")}
            className="ml-3 text-red-500 hover:text-red-300"
          >
            ✕
          </button>
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex gap-1 mb-6 bg-[#1a1d2e] border border-[#2a2d3e] rounded-lg p-1 w-fit">
        {TABS.map(({ key, label }) => {
          const count = countForTab(key);
          return (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={`px-3 py-1.5 text-sm rounded-md transition-colors flex items-center gap-1.5 ${
                tab === key
                  ? "bg-blue-600/30 text-blue-300 border border-blue-600/40"
                  : "text-slate-500 hover:text-slate-300"
              }`}
            >
              {label}
              {count > 0 && (
                <span
                  className={`text-xs px-1.5 py-0.5 rounded-full ${
                    tab === key
                      ? "bg-blue-700/40 text-blue-300"
                      : "bg-[#2a2d3e] text-slate-500"
                  }`}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Content */}
      {loading ? (
        <div className="text-slate-500 text-sm">Loading remediations…</div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 text-slate-500">
          <p className="text-4xl mb-4">⬢</p>
          {tab === "all" ? (
            <>
              <p>No remediation jobs yet.</p>
              <p className="text-sm mt-2">
                Open a finding and click <strong>Propose Remediation</strong> to get started.
              </p>
            </>
          ) : (
            <p>No {tab} jobs.</p>
          )}
        </div>
      ) : (
        <div className="flex flex-col gap-3 max-w-2xl">
          {filtered.map((job) => (
            <RemediationProposalCard
              key={job.job_id}
              job={job}
              onApprove={(id) => openModal(id, "approve")}
              onReject={(id) => openModal(id, "reject")}
            />
          ))}
        </div>
      )}

      {/* Approval / Rejection Modal */}
      {modal && (
        <ApprovalModal
          job={modal.job}
          mode={modal.mode}
          loading={modalLoading}
          onConfirm={handleConfirm}
          onCancel={() => setModal(null)}
        />
      )}
    </div>
  );
}
