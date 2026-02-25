"use client";

import { type RemediationJob } from "@/lib/api";

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

interface Props {
  job: RemediationJob;
  mode: "approve" | "reject";
  loading: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ApprovalModal({ job, mode, loading, onConfirm, onCancel }: Props) {
  const label = ACTION_LABELS[job.proposal.action] ?? job.proposal.action;
  const isApprove = mode === "approve";

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div className="bg-[#1a1d2e] border border-[#2a2d3e] rounded-2xl p-6 max-w-md w-full shadow-2xl">
        {/* Title */}
        <h2 className="text-slate-100 text-lg font-semibold mb-1">
          {isApprove ? "Approve Remediation" : "Reject Remediation"}
        </h2>
        <p className="text-slate-500 text-sm mb-4">
          {isApprove
            ? "This will immediately execute the following AWS change. This action is reversible."
            : "The remediation job will be discarded. No AWS changes will be made."}
        </p>

        {/* Action summary */}
        <div className="bg-[#0f1117] border border-[#2a2d3e] rounded-xl p-4 mb-5">
          <p className="text-slate-300 font-medium text-sm mb-2">{label}</p>
          <p className="text-slate-500 text-xs leading-relaxed">{job.proposal.description}</p>
          <div className="flex flex-wrap gap-3 mt-3 text-xs text-slate-600">
            <span>
              <span className="text-slate-700">region</span>{" "}
              <span className="font-mono text-slate-500">{job.proposal.region}</span>
            </span>
            <span>
              <span className="text-slate-700">account</span>{" "}
              <span className="font-mono text-slate-500">{job.proposal.account_id}</span>
            </span>
          </div>
        </div>

        {/* Confirmation warning (approve only) */}
        {isApprove && (
          <div className="bg-amber-950/30 border border-amber-900/40 rounded-lg px-3 py-2 mb-5">
            <p className="text-amber-400 text-xs">
              SENTINEL will execute this change immediately in your AWS account.
              Confirm you have reviewed the action above.
            </p>
          </div>
        )}

        {/* Buttons */}
        <div className="flex gap-3">
          <button
            onClick={onCancel}
            disabled={loading}
            className="flex-1 bg-transparent border border-[#2a2d3e] text-slate-400 hover:text-slate-200 text-sm py-2.5 px-4 rounded-lg transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={loading}
            className={`flex-1 text-sm font-medium py-2.5 px-4 rounded-lg transition-colors disabled:opacity-50 ${
              isApprove
                ? "bg-green-700/30 hover:bg-green-700/50 border border-green-700/60 text-green-300"
                : "bg-red-900/30 hover:bg-red-900/50 border border-red-900/60 text-red-400"
            }`}
          >
            {loading ? "Processing…" : isApprove ? "Confirm Approve" : "Confirm Reject"}
          </button>
        </div>
      </div>
    </div>
  );
}
