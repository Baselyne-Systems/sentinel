"use client";

import type { Finding } from "@/lib/api";

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "border-l-red-500 bg-red-900/10",
  HIGH: "border-l-orange-500 bg-orange-900/10",
  MEDIUM: "border-l-yellow-500 bg-yellow-900/10",
  LOW: "border-l-blue-500 bg-blue-900/10",
};

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-900/50 text-red-300",
  HIGH: "bg-orange-900/50 text-orange-300",
  MEDIUM: "bg-yellow-900/50 text-yellow-300",
  LOW: "bg-blue-900/50 text-blue-300",
};

const RESOURCE_TYPE_COLORS: Record<string, string> = {
  IAMRole: "text-blue-400",
  IAMUser: "text-blue-400",
  IAMPolicy: "text-blue-400",
  EC2Instance: "text-orange-400",
  LambdaFunction: "text-orange-400",
  S3Bucket: "text-green-400",
  RDSInstance: "text-purple-400",
  SecurityGroup: "text-red-400",
  VPC: "text-red-400",
};

export function FindingCard({
  finding,
  onClick,
}: {
  finding: Finding;
  onClick?: (nodeId: string) => void;
}) {
  const style = SEVERITY_STYLES[finding.severity] ?? "border-l-slate-500";
  const badge = SEVERITY_BADGE[finding.severity] ?? "bg-slate-700 text-slate-300";
  const typeColor = RESOURCE_TYPE_COLORS[finding.resource_type] ?? "text-slate-300";

  return (
    <div
      className={`border-l-2 rounded-r-lg p-4 ${style} cursor-pointer hover:brightness-110 transition-all`}
      onClick={() => onClick?.(finding.node_id)}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className={`text-sm font-mono truncate ${typeColor}`}>{finding.node_id}</p>
          <p className="text-xs text-slate-500 mt-0.5">
            <span className={typeColor}>{finding.resource_type}</span>
            {finding.region && (
              <span className="text-slate-600"> · {finding.region}</span>
            )}
          </p>
        </div>
        <span className={`shrink-0 text-xs px-2 py-0.5 rounded font-mono ${badge}`}>
          {finding.severity}
        </span>
      </div>

      {/* Flags */}
      {finding.posture_flags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {finding.posture_flags
            .filter((f) => !["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(f))
            .map((flag) => (
              <span
                key={flag}
                className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono"
              >
                {flag}
              </span>
            ))}
        </div>
      )}
    </div>
  );
}
