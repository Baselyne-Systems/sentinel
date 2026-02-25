"use client";

import { type RemediationJob, type JobStatus } from "@/lib/api";

const ACTION_LABELS: Record<string, string> = {
  s3_block_public_access: "Block S3 Public Access",
  s3_enable_versioning: "Enable S3 Versioning",
  s3_enable_sse: "Enable S3 Encryption",
  s3_enable_logging: "Enable S3 Access Logging",
  ec2_enable_ebs_encryption: "Enable EBS Encryption by Default",
  cloudtrail_enable: "Enable CloudTrail",
  cloudtrail_log_validation: "Enable CloudTrail Log Validation",
  rds_disable_public_access: "Disable RDS Public Access",
};

const ACTION_ICONS: Record<string, string> = {
  s3_block_public_access: "⬡",
  s3_enable_versioning: "⬡",
  s3_enable_sse: "⬡",
  s3_enable_logging: "⬡",
  ec2_enable_ebs_encryption: "◈",
  cloudtrail_enable: "◉",
  cloudtrail_log_validation: "◉",
  rds_disable_public_access: "▣",
};

const STATUS_STYLES: Record<JobStatus, string> = {
  pending: "bg-amber-900/30 text-amber-300 border-amber-700",
  approved: "bg-blue-900/30 text-blue-300 border-blue-700",
  rejected: "bg-slate-800/60 text-slate-500 border-slate-600",
  executing: "bg-purple-900/30 text-purple-300 border-purple-700",
  completed: "bg-green-900/30 text-green-300 border-green-700",
  failed: "bg-red-900/30 text-red-300 border-red-700",
};

const STATUS_DOTS: Record<JobStatus, string> = {
  pending: "bg-amber-400",
  approved: "bg-blue-400",
  rejected: "bg-slate-500",
  executing: "bg-purple-400 animate-pulse",
  completed: "bg-green-400",
  failed: "bg-red-400",
};

interface Props {
  job: RemediationJob;
  onApprove?: (jobId: string) => void;
  onReject?: (jobId: string) => void;
}

export function RemediationProposalCard({ job, onApprove, onReject }: Props) {
  const { proposal, status } = job;
  const label = ACTION_LABELS[proposal.action] ?? proposal.action;
  const icon = ACTION_ICONS[proposal.action] ?? "◉";
  const statusStyle = STATUS_STYLES[status];
  const dotStyle = STATUS_DOTS[status];
  const isPending = status === "pending";

  return (
    <div className="bg-[#13152a] border border-[#2a2d3e] rounded-xl p-5 flex flex-col gap-3">
      {/* Header row */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-blue-400 text-base shrink-0">{icon}</span>
          <h3 className="text-slate-100 font-semibold text-sm truncate">{label}</h3>
        </div>
        <span
          className={`shrink-0 flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-xs font-medium ${statusStyle}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${dotStyle}`} />
          {status}
        </span>
      </div>

      {/* Resource info */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
        <span>
          <span className="text-slate-600">resource</span>{" "}
          <span className="font-mono text-slate-400">{proposal.resource_type}</span>
        </span>
        <span>
          <span className="text-slate-600">region</span>{" "}
          <span className="font-mono text-slate-400">{proposal.region}</span>
        </span>
        <span>
          <span className="text-slate-600">account</span>{" "}
          <span className="font-mono text-slate-400">{proposal.account_id}</span>
        </span>
      </div>

      {/* Description */}
      <p className="text-slate-300 text-sm leading-relaxed">{proposal.description}</p>

      {/* Risk reduction badge */}
      <div className="bg-[#0f1117] border border-[#2a2d3e] rounded-lg px-3 py-2">
        <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Risk Reduction</p>
        <p className="text-slate-400 text-xs leading-relaxed">{proposal.risk_reduction}</p>
      </div>

      {/* Execution output */}
      {status === "completed" && job.output && (
        <div className="bg-green-950/30 border border-green-900/40 rounded-lg px-3 py-2">
          <p className="text-xs text-green-500 uppercase tracking-wider mb-1">Output</p>
          <pre className="text-green-400 text-xs overflow-auto">
            {JSON.stringify(job.output, null, 2)}
          </pre>
        </div>
      )}

      {/* Error */}
      {status === "failed" && job.error && (
        <div className="bg-red-950/30 border border-red-900/40 rounded-lg px-3 py-2">
          <p className="text-xs text-red-500 uppercase tracking-wider mb-1">Error</p>
          <p className="text-red-400 text-xs font-mono break-all">{job.error}</p>
        </div>
      )}

      {/* Timestamps */}
      <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-slate-600">
        <span>Proposed {new Date(job.proposed_at).toLocaleString()}</span>
        {job.approved_at && (
          <span>Approved {new Date(job.approved_at).toLocaleString()}</span>
        )}
        {job.completed_at && (
          <span>Completed {new Date(job.completed_at).toLocaleString()}</span>
        )}
      </div>

      {/* Action buttons — only shown for pending jobs */}
      {isPending && (onApprove || onReject) && (
        <div className="flex gap-2 pt-1">
          {onApprove && (
            <button
              onClick={() => onApprove(job.job_id)}
              className="flex-1 bg-green-700/20 hover:bg-green-700/40 border border-green-700/50 text-green-300 text-sm font-medium py-2 px-4 rounded-lg transition-colors"
            >
              Approve
            </button>
          )}
          {onReject && (
            <button
              onClick={() => onReject(job.job_id)}
              className="flex-1 bg-red-900/20 hover:bg-red-900/40 border border-red-900/50 text-red-400 text-sm font-medium py-2 px-4 rounded-lg transition-colors"
            >
              Reject
            </button>
          )}
        </div>
      )}
    </div>
  );
}
