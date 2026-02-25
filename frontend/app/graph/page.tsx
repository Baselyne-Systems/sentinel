"use client";

import { useEffect, useState, useCallback } from "react";
import dynamic from "next/dynamic";
import { graphApi, type GraphNode, type GraphEdge } from "@/lib/api";
import { NodeDetailDrawer } from "@/components/graph/NodeDetailDrawer";

// Cytoscape must be client-side only (no SSR)
const CytoscapeCanvas = dynamic(
  () => import("@/components/graph/CytoscapeCanvas").then((m) => m.CytoscapeCanvas),
  { ssr: false, loading: () => <div className="text-slate-500 text-sm p-4">Loading graph…</div> }
);

const RESOURCE_TYPES = [
  { value: "", label: "All Types" },
  { value: "S3Bucket", label: "S3 Bucket" },
  { value: "EC2Instance", label: "EC2 Instance" },
  { value: "SecurityGroup", label: "Security Group" },
  { value: "RDSInstance", label: "RDS Instance" },
  { value: "IAMRole", label: "IAM Role" },
  { value: "IAMUser", label: "IAM User" },
  { value: "IAMPolicy", label: "IAM Policy" },
  { value: "LambdaFunction", label: "Lambda Function" },
  { value: "VPC", label: "VPC" },
  { value: "Subnet", label: "Subnet" },
];

const SEVERITIES = [
  { value: "", label: "All" },
  { value: "CRITICAL", label: "Critical" },
  { value: "HIGH", label: "High" },
  { value: "MEDIUM", label: "Medium" },
  { value: "LOW", label: "Low" },
];

export default function GraphExplorerPage() {
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [search, setSearch] = useState("");

  const loadGraph = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const allNodes = await graphApi.listNodes({
        type: typeFilter || undefined,
        limit: 500,
      });

      // Apply severity filter client-side
      const filtered =
        severityFilter
          ? allNodes.filter((n) => n.posture_flags?.includes(severityFilter))
          : allNodes;

      // Apply search filter
      const searched = search
        ? filtered.filter(
            (n) =>
              n.node_id.toLowerCase().includes(search.toLowerCase()) ||
              (n.name ?? "").toLowerCase().includes(search.toLowerCase())
          )
        : filtered;

      setNodes(searched);

      // Build edges from neighbor queries for visible nodes (limit to keep it fast)
      if (searched.length > 0 && searched.length <= 100) {
        const neighborPromises = searched.slice(0, 20).map((n) =>
          graphApi.getNeighbors(n.node_id, 1).catch(() => null)
        );
        const results = await Promise.all(neighborPromises);
        const allEdges: GraphEdge[] = [];
        const seenEdges = new Set<string>();

        for (const result of results) {
          if (!result) continue;
          for (const edge of result.edges) {
            const key = `${edge.from}-${edge.to}-${edge.type}`;
            if (!seenEdges.has(key)) {
              seenEdges.add(key);
              allEdges.push(edge);
            }
          }
        }
        setEdges(allEdges);
      } else {
        setEdges([]);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [typeFilter, severityFilter, search]);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  const handleNodeClick = useCallback((node: GraphNode) => {
    setSelectedNode(node);
    // Optionally load subgraph for this node
  }, []);

  return (
    <div className="flex h-full">
      {/* Left filter panel */}
      <div className="w-52 shrink-0 bg-[#1a1d2e] border-r border-[#2a2d3e] p-4 flex flex-col gap-4">
        <div>
          <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">
            Search
          </label>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="node ID or name…"
            className="w-full bg-[#0f1117] border border-[#2a2d3e] text-slate-300 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div>
          <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">
            Resource Type
          </label>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="w-full bg-[#0f1117] border border-[#2a2d3e] text-slate-300 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-blue-500"
          >
            {RESOURCE_TYPES.map(({ value, label }) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">
            Severity
          </label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-[#0f1117] border border-[#2a2d3e] text-slate-300 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-blue-500"
          >
            {SEVERITIES.map(({ value, label }) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>

        {/* Legend */}
        <div className="mt-auto">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Node Types</p>
          {[
            { color: "#3b82f6", label: "IAM" },
            { color: "#f97316", label: "Compute" },
            { color: "#22c55e", label: "Storage" },
            { color: "#ef4444", label: "Network" },
            { color: "#a855f7", label: "Database" },
          ].map(({ color, label }) => (
            <div key={label} className="flex items-center gap-2 py-0.5">
              <div
                className="w-3 h-3 rounded-full shrink-0"
                style={{ backgroundColor: color }}
              />
              <span className="text-xs text-slate-400">{label}</span>
            </div>
          ))}

          <p className="text-xs text-slate-500 uppercase tracking-wider mb-2 mt-4">Border = Severity</p>
          {[
            { color: "#dc2626", label: "Critical" },
            { color: "#ea580c", label: "High" },
            { color: "#ca8a04", label: "Medium" },
            { color: "#2563eb", label: "Low" },
          ].map(({ color, label }) => (
            <div key={label} className="flex items-center gap-2 py-0.5">
              <div
                className="w-3 h-3 rounded-full shrink-0 border-2"
                style={{ borderColor: color, backgroundColor: "transparent" }}
              />
              <span className="text-xs text-slate-400">{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Graph canvas */}
      <div className="flex-1 relative overflow-hidden">
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center bg-[#0f1117]/80 z-10">
            <span className="text-slate-400 text-sm">Loading graph…</span>
          </div>
        )}
        {error && (
          <div className="absolute top-4 left-4 right-4 p-3 bg-red-900/30 border border-red-700 rounded text-red-300 text-sm z-10">
            {error}
          </div>
        )}
        {!loading && nodes.length === 0 && !error && (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500">
            <p className="text-4xl mb-4">◈</p>
            <p>No nodes to display.</p>
            <p className="text-sm mt-2">Run a scan from the Dashboard first.</p>
          </div>
        )}
        <CytoscapeCanvas nodes={nodes} edges={edges} onNodeClick={handleNodeClick} />

        {/* Node count badge */}
        <div className="absolute bottom-4 left-4 bg-[#1a1d2e]/90 border border-[#2a2d3e] rounded-md px-3 py-1.5 text-xs text-slate-400">
          {nodes.length} nodes · {edges.length} edges
        </div>
      </div>

      {/* Right detail drawer */}
      {selectedNode && (
        <NodeDetailDrawer
          node={selectedNode}
          onClose={() => setSelectedNode(null)}
        />
      )}
    </div>
  );
}
