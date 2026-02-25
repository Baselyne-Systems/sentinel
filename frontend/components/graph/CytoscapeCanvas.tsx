"use client";

import { useEffect, useRef, useCallback } from "react";
import type cytoscape from "cytoscape";
import type { GraphNode, GraphEdge } from "@/lib/api";

// Node type → base color
const NODE_COLORS: Record<string, string> = {
  IAMRole: "#3b82f6",
  IAMUser: "#3b82f6",
  IAMPolicy: "#60a5fa",
  EC2Instance: "#f97316",
  LambdaFunction: "#fb923c",
  S3Bucket: "#22c55e",
  RDSInstance: "#a855f7",
  SecurityGroup: "#ef4444",
  VPC: "#f87171",
  Subnet: "#fca5a5",
  Region: "#94a3b8",
  AWSAccount: "#e2e8f0",
};

// Highest posture severity → border color
const SEVERITY_BORDER: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#2563eb",
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function getNodeBorderColor(flags: string[]): string {
  for (const sev of SEVERITY_ORDER) {
    if (flags.includes(sev)) return SEVERITY_BORDER[sev]!;
  }
  return "#2a2d3e";
}

function buildCytoElements(
  nodes: GraphNode[],
  edges: GraphEdge[]
): cytoscape.ElementDefinition[] {
  const elements: cytoscape.ElementDefinition[] = [];

  for (const node of nodes) {
    elements.push({
      data: {
        id: node.node_id,
        label:
          node.name ||
          node.function_name ||
          node.instance_id ||
          node.db_id ||
          node.node_id.slice(0, 20),
        resource_type: node.resource_type,
        posture_flags: node.posture_flags ?? [],
        color: NODE_COLORS[node.resource_type] ?? "#94a3b8",
        borderColor: getNodeBorderColor(node.posture_flags ?? []),
        raw: node,
      },
    });
  }

  for (const edge of edges) {
    if (!edge.from || !edge.to) continue;
    elements.push({
      data: {
        id: `${edge.from}-${edge.to}-${edge.type}`,
        source: edge.from,
        target: edge.to,
        label: edge.type,
      },
    });
  }

  return elements;
}

interface CytoscapeCanvasProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (node: GraphNode) => void;
}

export function CytoscapeCanvas({ nodes, edges, onNodeClick }: CytoscapeCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const initCytoscape = useCallback(async () => {
    if (!containerRef.current) return;

    const [cytoscapeModule, colaModule] = await Promise.all([
      import("cytoscape"),
      import("cytoscape-cola"),
    ]);

    const cytoscape = cytoscapeModule.default;
    const cola = colaModule.default;

    // Register cola layout (idempotent)
    try {
      cytoscape.use(cola as Parameters<typeof cytoscape.use>[0]);
    } catch {
      // Already registered
    }

    const elements = buildCytoElements(nodes, edges);

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)" as unknown as string,
            "border-color": "data(borderColor)" as unknown as string,
            "border-width": 2,
            label: "data(label)",
            "font-size": 9,
            color: "#e2e8f0",
            "text-outline-color": "#0f1117",
            "text-outline-width": 1,
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": 4,
            width: 36,
            height: 36,
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-width": 4,
            "border-color": "#60a5fa",
          },
        },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": "#2a2d3e",
            "target-arrow-color": "#2a2d3e",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "font-size": 7,
            color: "#64748b",
            label: "",
          },
        },
        {
          selector: "edge:selected",
          style: {
            label: "data(label)",
            "line-color": "#3b82f6",
            "target-arrow-color": "#3b82f6",
          },
        },
      ],
      layout: {
        name: "cola",
        animate: true,
        randomize: false,
        nodeSpacing: 40,
        edgeLength: 120,
      } as cytoscape.LayoutOptions,
    });

    cy.on("tap", "node", (evt) => {
      const raw = evt.target.data("raw") as GraphNode;
      onNodeClick?.(raw);
    });

    cyRef.current = cy;
  }, [nodes, edges, onNodeClick]);

  useEffect(() => {
    initCytoscape();
    return () => {
      cyRef.current?.destroy();
    };
  }, [initCytoscape]);

  return (
    <div
      ref={containerRef}
      className="w-full h-full bg-[#0f1117]"
      style={{ minHeight: "400px" }}
    />
  );
}
