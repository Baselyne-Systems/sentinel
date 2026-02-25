"use client";

import { useEffect, useState } from "react";
import { postureApi, type Finding, type Severity } from "@/lib/api";
import { FindingCard } from "@/components/posture/FindingCard";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const RESOURCE_TYPES = [
  "S3Bucket",
  "EC2Instance",
  "SecurityGroup",
  "RDSInstance",
  "IAMRole",
  "IAMUser",
  "IAMPolicy",
  "LambdaFunction",
  "VPC",
];

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<Severity | "">("");
  const [typeFilter, setTypeFilter] = useState("");

  useEffect(() => {
    setLoading(true);
    postureApi
      .getFindings({
        severity: severityFilter || undefined,
        resource_type: typeFilter || undefined,
      })
      .then(setFindings)
      .finally(() => setLoading(false));
  }, [severityFilter, typeFilter]);

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-100">Security Findings</h1>
        <p className="text-slate-500 text-sm mt-1">
          {findings.length} finding{findings.length !== 1 ? "s" : ""}
        </p>
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-6">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Severity | "")}
          className="bg-[#1a1d2e] border border-[#2a2d3e] text-slate-300 text-sm rounded-md px-3 py-2 focus:outline-none focus:border-blue-500"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="bg-[#1a1d2e] border border-[#2a2d3e] text-slate-300 text-sm rounded-md px-3 py-2 focus:outline-none focus:border-blue-500"
        >
          <option value="">All Resource Types</option>
          {RESOURCE_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>

        {(severityFilter || typeFilter) && (
          <button
            onClick={() => {
              setSeverityFilter("");
              setTypeFilter("");
            }}
            className="text-sm text-slate-500 hover:text-slate-300 px-2"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Findings list */}
      {loading ? (
        <div className="text-slate-500 text-sm">Loading findings…</div>
      ) : findings.length === 0 ? (
        <div className="text-center py-16 text-slate-500">
          <p className="text-4xl mb-4">◉</p>
          <p>No findings match your filters.</p>
          <p className="text-sm mt-2">Run a scan from the Dashboard to discover issues.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-2 max-w-3xl">
          {findings.map((f) => (
            <FindingCard key={f.node_id + f.severity} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}
