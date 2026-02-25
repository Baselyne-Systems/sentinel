"use client";

import type { GraphNode } from "@/lib/api";

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-900/50 text-red-300",
  HIGH: "bg-orange-900/50 text-orange-300",
  MEDIUM: "bg-yellow-900/50 text-yellow-300",
  LOW: "bg-blue-900/50 text-blue-300",
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function getHighestSeverity(flags: string[]): string | null {
  for (const sev of SEVERITY_ORDER) {
    if (flags.includes(sev)) return sev;
  }
  return null;
}

function PropRow({ label, value }: { label: string; value: string | null | undefined }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex gap-2 py-1.5 border-b border-[#2a2d3e] last:border-0">
      <span className="text-slate-500 text-xs w-36 shrink-0">{label}</span>
      <span className="text-slate-300 text-xs font-mono break-all">{String(value)}</span>
    </div>
  );
}

export function NodeDetailDrawer({
  node,
  onClose,
}: {
  node: GraphNode;
  onClose: () => void;
}) {
  const flags = node.posture_flags ?? [];
  const severity = getHighestSeverity(flags);
  const specificFlags = flags.filter((f) => !SEVERITY_ORDER.includes(f));

  // Extract display-worthy properties
  const displayProps: Array<[string, string | null | undefined]> = [
    ["Node ID", node.node_id],
    ["Resource Type", node.resource_type],
    ["Account ID", node.account_id],
    ["Region", node.region],
    ["Name", node.name],
    ["Instance ID", node.instance_id],
    ["Group ID", node.group_id],
    ["VPC ID", node.vpc_id],
    ["DB ID", node.db_id],
    ["ARN", node.arn],
    ["Function Name", node.function_name],
    ["Discovered", node.discovered_at],
  ];

  return (
    <div className="w-80 shrink-0 bg-[#1a1d2e] border-l border-[#2a2d3e] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-[#2a2d3e]">
        <span className="text-sm font-semibold text-slate-200 truncate">Node Detail</span>
        <button
          onClick={onClose}
          className="text-slate-500 hover:text-slate-300 text-lg leading-none"
        >
          ×
        </button>
      </div>

      {/* Severity */}
      {severity && (
        <div className={`px-4 py-2 text-xs font-mono ${SEVERITY_BADGE[severity]}`}>
          ● {severity} severity
        </div>
      )}

      {/* Properties */}
      <div className="flex-1 overflow-y-auto p-4">
        <div className="mb-4">
          {displayProps.map(([label, value]) => (
            <PropRow key={label} label={label} value={value as string} />
          ))}
        </div>

        {/* Tags */}
        {Object.keys(node.tags ?? {}).length > 0 && (
          <div className="mb-4">
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Tags</p>
            {Object.entries(node.tags!).map(([k, v]) => (
              <div key={k} className="flex gap-2 py-1">
                <span className="text-slate-500 text-xs">{k}:</span>
                <span className="text-slate-300 text-xs font-mono">{v}</span>
              </div>
            ))}
          </div>
        )}

        {/* Posture flags */}
        {specificFlags.length > 0 && (
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Posture Flags</p>
            <div className="flex flex-col gap-1">
              {specificFlags.map((flag) => (
                <span
                  key={flag}
                  className="text-xs bg-red-900/30 text-red-300 border border-red-800 px-2 py-1 rounded font-mono"
                >
                  {flag}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
