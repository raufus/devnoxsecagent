import { useParams } from "wouter";
import { useGetScanGraph, useGetScan } from "@workspace/api-client-react";
import { Layout } from "@/components/layout";
import { useEffect } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  MarkerType,
  BackgroundVariant,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Card } from "@/components/ui/card";
import { Network, Globe, Server, AlertTriangle, Zap, Mail, Database, Cpu } from "lucide-react";

const NODE_TYPE_CONFIG: Record<string, { color: string; borderColor: string; Icon: React.FC<{ className?: string }> }> = {
  domain: { color: "#0f1a0f", borderColor: "#00ff80", Icon: Globe },
  subdomain: { color: "#0f1520", borderColor: "#22d3ee", Icon: Network },
  ip: { color: "#1a1000", borderColor: "#eab308", Icon: Database },
  server: { color: "#1a0820", borderColor: "#a855f7", Icon: Server },
  vulnerability: { color: "#1a0800", borderColor: "#f97316", Icon: AlertTriangle },
  exploit: { color: "#1a0000", borderColor: "#ef4444", Icon: Zap },
  email: { color: "#0f1015", borderColor: "#8b5cf6", Icon: Mail },
  service: { color: "#0f1a18", borderColor: "#2dd4bf", Icon: Cpu },
};

const SEVERITY_GLOW: Record<string, string> = {
  critical: "0 0 12px #ef4444",
  high: "0 0 10px #f97316",
  medium: "0 0 8px #eab308",
  low: "0 0 6px #3b82f6",
  info: "0 0 4px #6b7280",
  none: "none",
};

function CustomNode({ data }: { data: { label: string; nodeType: string; severity: string; info?: string } }) {
  const config = NODE_TYPE_CONFIG[data.nodeType] || NODE_TYPE_CONFIG.service;
  const Icon = config.Icon;
  const glow = SEVERITY_GLOW[data.severity] || "none";

  return (
    <div
      style={{
        background: config.color,
        border: `1px solid ${config.borderColor}`,
        borderRadius: 6,
        padding: "8px 12px",
        minWidth: 120,
        maxWidth: 180,
        boxShadow: glow !== "none" ? glow : `0 0 6px ${config.borderColor}40`,
        fontFamily: "monospace",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 2 }}>
        <Icon className="w-3 h-3" style={{ color: config.borderColor, flexShrink: 0 }} />
        <span style={{ fontSize: 9, color: config.borderColor, textTransform: "uppercase", letterSpacing: "0.1em" }}>
          {data.nodeType}
        </span>
        {data.severity && data.severity !== "none" && (
          <span style={{
            fontSize: 8,
            padding: "1px 4px",
            border: `1px solid ${config.borderColor}40`,
            borderRadius: 3,
            color: config.borderColor,
            marginLeft: "auto",
          }}>
            {data.severity.toUpperCase()}
          </span>
        )}
      </div>
      <div style={{ fontSize: 11, color: "#e2e8f0", wordBreak: "break-word", lineHeight: 1.3 }}>
        {data.label}
      </div>
    </div>
  );
}

const nodeTypes = { custom: CustomNode };

function layoutNodes(nodes: Array<{ id: string; nodeType: string; label: string; severity: string; data?: Record<string, unknown> }>) {
  const TYPE_LAYER: Record<string, number> = {
    domain: 0,
    subdomain: 1,
    ip: 1,
    server: 2,
    vulnerability: 3,
    exploit: 4,
    email: 1,
    service: 2,
  };

  const byLayer: Record<number, typeof nodes> = {};
  for (const n of nodes) {
    const layer = TYPE_LAYER[n.nodeType] ?? 2;
    if (!byLayer[layer]) byLayer[layer] = [];
    byLayer[layer].push(n);
  }

  const LAYER_X: Record<number, number> = { 0: 100, 1: 350, 2: 650, 3: 950, 4: 1250 };
  const result: Node[] = [];

  for (const [layer, layerNodes] of Object.entries(byLayer)) {
    const layerNum = Number(layer);
    const x = LAYER_X[layerNum] ?? layerNum * 300 + 100;
    const totalHeight = layerNodes.length * 100;
    const startY = Math.max(50, 300 - totalHeight / 2);

    layerNodes.forEach((node, i) => {
      result.push({
        id: node.id,
        type: "custom",
        position: { x, y: startY + i * 110 },
        data: {
          label: node.label,
          nodeType: node.nodeType,
          severity: node.severity,
        },
      });
    });
  }

  return result;
}

export default function GraphPage() {
  const { id } = useParams();
  const { data: scanData } = useGetScan(id!);
  const { data, isLoading } = useGetScanGraph(id!);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    if (!data?.nodes) return;
    setNodes(layoutNodes(data.nodes.map(n => ({
      id: n.id,
      nodeType: n.nodeType,
      label: n.label,
      severity: n.severity,
    }))));
    setEdges(data.edges.map(e => ({
      id: e.id,
      source: e.sourceId,
      target: e.targetId,
      label: e.label || e.edgeType,
      animated: e.edgeType === "vulnerable_to" || e.edgeType === "exploited_via",
      style: {
        stroke: e.edgeType === "exploited_via" ? "#ef4444" :
                e.edgeType === "vulnerable_to" ? "#f97316" :
                e.edgeType === "resolves_to" ? "#eab308" :
                "#374151",
        strokeWidth: e.edgeType === "exploited_via" ? 2 : 1.5,
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: e.edgeType === "exploited_via" ? "#ef4444" : "#4b5563",
      },
      labelStyle: { fill: "#9ca3af", fontSize: 9, fontFamily: "monospace" },
      labelBgStyle: { fill: "transparent" },
    })));
  }, [data]);

  if (isLoading) {
    return (
      <Layout>
        <div className="flex items-center gap-3 p-8 justify-center font-mono text-sm text-muted-foreground">
          <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          BUILDING ATTACK GRAPH...
        </div>
      </Layout>
    );
  }

  if (!data?.nodes?.length) {
    return (
      <Layout>
        <div className="flex flex-col gap-4 animate-in fade-in duration-500">
          <header className="border-b border-primary/20 pb-4">
            <h1 className="text-2xl font-display font-bold">GRAPH_INTELLIGENCE</h1>
            <p className="text-xs font-mono text-muted-foreground mt-1">MALTEGO-STYLE ATTACK PATH VISUALIZATION</p>
          </header>
          <div className="p-8 text-center">
            <Network className="w-12 h-12 text-muted-foreground mx-auto mb-3 opacity-40" />
            <p className="font-mono text-sm text-muted-foreground">No attack graph data available yet.</p>
            <p className="font-mono text-xs text-muted-foreground mt-1">Complete a Full or Deep scan to generate the graph.</p>
          </div>
        </div>
      </Layout>
    );
  }

  const nodeTypes2 = {
    domain: { color: "#00ff80", count: data.nodes.filter(n => n.nodeType === "domain").length },
    subdomain: { color: "#22d3ee", count: data.nodes.filter(n => n.nodeType === "subdomain").length },
    ip: { color: "#eab308", count: data.nodes.filter(n => n.nodeType === "ip").length },
    server: { color: "#a855f7", count: data.nodes.filter(n => n.nodeType === "server").length },
    vulnerability: { color: "#f97316", count: data.nodes.filter(n => n.nodeType === "vulnerability").length },
    exploit: { color: "#ef4444", count: data.nodes.filter(n => n.nodeType === "exploit").length },
  };

  return (
    <Layout>
      <div className="flex flex-col gap-4 animate-in fade-in duration-500 h-full">
        <header className="flex items-center justify-between border-b border-primary/20 pb-3 shrink-0">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono mb-1">
              <span className="text-muted-foreground">TARGET:</span>
              <span className="text-cyan-400 px-2 py-0.5 bg-cyan-400/10 border border-cyan-400/30 truncate max-w-xs text-xs">
                {scanData?.targetUrl || "—"}
              </span>
            </div>
            <h1 className="text-2xl font-display font-bold">GRAPH_INTELLIGENCE</h1>
            <p className="text-xs font-mono text-muted-foreground mt-1">
              MALTEGO-STYLE ATTACK PATH • {data.nodes.length} NODES • {data.edges.length} CONNECTIONS
            </p>
          </div>

          {/* Legend */}
          <div className="hidden md:flex items-center gap-3 text-xs font-mono">
            {Object.entries(nodeTypes2).filter(([, v]) => v.count > 0).map(([type, { color, count }]) => (
              <div key={type} className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-muted-foreground capitalize">{type} ({count})</span>
              </div>
            ))}
          </div>
        </header>

        <div className="flex-1 rounded border border-primary/20 overflow-hidden" style={{ height: "calc(100vh - 200px)", minHeight: 500 }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.2}
            maxZoom={2}
            defaultEdgeOptions={{
              style: { stroke: "#374151" },
            }}
          >
            <Background
              variant={BackgroundVariant.Dots}
              gap={20}
              size={1}
              color="#1a2a1a"
            />
            <Controls
              style={{
                background: "#0d1117",
                border: "1px solid #1f3a1f",
                borderRadius: 4,
              }}
            />
            <MiniMap
              style={{
                background: "#0d1117",
                border: "1px solid #1f3a1f",
              }}
              nodeColor={(n) => {
                const config = NODE_TYPE_CONFIG[(n.data as { nodeType?: string })?.nodeType || "service"];
                return config?.borderColor || "#374151";
              }}
            />
          </ReactFlow>
        </div>

        {/* Attack path legend */}
        <div className="shrink-0 flex flex-wrap gap-4 text-xs font-mono text-muted-foreground pb-2">
          <div className="flex items-center gap-1.5"><div className="w-4 h-0.5 bg-yellow-400" /><span>resolves_to</span></div>
          <div className="flex items-center gap-1.5"><div className="w-4 h-0.5 bg-gray-600" /><span>has_subdomain / runs</span></div>
          <div className="flex items-center gap-1.5"><div className="w-4 h-0.5 bg-orange-400" /><span>vulnerable_to</span></div>
          <div className="flex items-center gap-1.5"><div className="w-4 h-0.5 bg-red-400" /><span>exploited_via</span></div>
        </div>
      </div>
    </Layout>
  );
}
