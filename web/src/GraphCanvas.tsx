import Icon from "./Icon";
import type { GraphEdge, GraphNode } from "./types";

const nodeColors: Record<GraphNode["kind"], string> = {
  Incident: "#ff6b7a",
  Asset: "#49d6b4",
  IPAddress: "#66a6ff",
  Domain: "#6c8cff",
  File: "#f4b860",
  Malware: "#c57bff",
  ThreatActor: "#ff8a5c",
  AttackTechnique: "#f16ba6",
  Identity: "#59c3ff",
  Process: "#69d4d0",
  URL: "#7d9cff",
  Hash: "#e5bd67",
  Vulnerability: "#ff7f6e",
  Alert: "#ff6577",
  Campaign: "#d48aff",
  DataSource: "#80a1b8",
};

const nodeGlyphs: Record<GraphNode["kind"], string> = {
  Incident: "!",
  Asset: "A",
  IPAddress: "IP",
  Domain: "D",
  File: "F",
  Malware: "M",
  ThreatActor: "TA",
  AttackTechnique: "T",
  Identity: "ID",
  Process: "P",
  URL: "U",
  Hash: "#",
  Vulnerability: "V",
  Alert: "!",
  Campaign: "C",
  DataSource: "DS",
};

type GraphCanvasProps = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedId: string;
  zoom: number;
  criticalOnly: boolean;
  onSelect: (nodeId: string) => void;
  onZoomChange: (zoom: number) => void;
};

export default function GraphCanvas({
  nodes,
  edges,
  selectedId,
  zoom,
  criticalOnly,
  onSelect,
  onZoomChange,
}: GraphCanvasProps) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const connectedIds = new Set<string>([selectedId]);
  edges.forEach((edge) => {
    if (edge.source === selectedId) connectedIds.add(edge.target);
    if (edge.target === selectedId) connectedIds.add(edge.source);
  });

  return (
    <div className="graph-stage">
      <div className="graph-controls" aria-label="Graph zoom controls">
        <button
          aria-label="Zoom in"
          onClick={() => onZoomChange(Math.min(1.3, Number((zoom + 0.1).toFixed(1))))}
          type="button"
        >
          <Icon name="plus" size={15} />
        </button>
        <button
          aria-label="Zoom out"
          onClick={() => onZoomChange(Math.max(0.7, Number((zoom - 0.1).toFixed(1))))}
          type="button"
        >
          <Icon name="minus" size={15} />
        </button>
        <button aria-label="Reset zoom" onClick={() => onZoomChange(1)} type="button">
          <Icon name="reset" size={15} />
        </button>
      </div>

      <div className="graph-legend" aria-label="Entity legend">
        <span><i className="legend-dot legend-dot--asset" />Asset</span>
        <span><i className="legend-dot legend-dot--ioc" />IOC</span>
        <span><i className="legend-dot legend-dot--threat" />Threat</span>
        <span><i className="legend-dot legend-dot--technique" />Technique</span>
      </div>

      <svg
        aria-label={`Threat graph with ${nodes.length} visible entities`}
        className="graph-svg"
        role="img"
        viewBox="0 0 900 500"
      >
        <defs>
          <pattern height="28" id="grid" patternUnits="userSpaceOnUse" width="28">
            <circle cx="1" cy="1" fill="#293646" r="0.8" />
          </pattern>
          <marker
            id="arrow"
            markerHeight="8"
            markerWidth="8"
            orient="auto"
            refX="7"
            refY="4"
          >
            <path d="M0,0 L8,4 L0,8 Z" fill="#46566a" />
          </marker>
          <marker
            id="arrow-critical"
            markerHeight="8"
            markerWidth="8"
            orient="auto"
            refX="7"
            refY="4"
          >
            <path d="M0,0 L8,4 L0,8 Z" fill="#ff6577" />
          </marker>
          <filter id="node-shadow" x="-100%" y="-100%" width="300%" height="300%">
            <feDropShadow dx="0" dy="4" floodColor="#000" floodOpacity=".42" stdDeviation="7" />
          </filter>
          <filter id="selected-glow" x="-100%" y="-100%" width="300%" height="300%">
            <feDropShadow dx="0" dy="0" floodColor="#7af5dc" floodOpacity=".55" stdDeviation="10" />
          </filter>
        </defs>
        <rect fill="url(#grid)" height="500" width="900" />

        <g
          className="graph-world"
          style={{
            transform: `translate(${450 * (1 - zoom)}px, ${250 * (1 - zoom)}px) scale(${zoom})`,
          }}
        >
          {edges.map((edge) => {
            const source = nodeMap.get(edge.source);
            const target = nodeMap.get(edge.target);
            if (!source || !target) return null;
            const isSelected = edge.source === selectedId || edge.target === selectedId;
            const isCritical = Boolean(edge.critical);
            const subdued = criticalOnly && !isCritical;
            const midpointX = (source.x + target.x) / 2;
            const midpointY = (source.y + target.y) / 2;
            return (
              <g
                className={`graph-edge ${isSelected ? "graph-edge--selected" : ""} ${
                  isCritical ? "graph-edge--critical" : ""
                } ${
                  isCritical && criticalOnly ? "graph-edge--focus" : ""
                } ${subdued ? "graph-edge--subdued" : ""}`}
                key={edge.id}
              >
                <line
                  markerEnd={`url(#${isCritical && criticalOnly ? "arrow-critical" : "arrow"})`}
                  x1={source.x}
                  x2={target.x}
                  y1={source.y}
                  y2={target.y}
                />
                {(isSelected || (criticalOnly && isCritical)) && (
                  <g className="edge-label">
                    <rect
                      height="20"
                      rx="10"
                      width={edge.label.length * 6.2 + 16}
                      x={midpointX - (edge.label.length * 6.2 + 16) / 2}
                      y={midpointY - 10}
                    />
                    <text dominantBaseline="central" textAnchor="middle" x={midpointX} y={midpointY}>
                      {edge.label}
                    </text>
                  </g>
                )}
              </g>
            );
          })}

          {nodes.map((node) => {
            const selected = node.id === selectedId;
            const dimmed = criticalOnly && !connectedIds.has(node.id) && node.risk !== "critical";
            const radius = node.kind === "Incident" ? 35 : node.kind === "ThreatActor" ? 31 : 27;
            return (
              <g
                aria-label={`${node.kind}: ${node.label}`}
                className={`graph-node ${selected ? "graph-node--selected" : ""} ${
                  dimmed ? "graph-node--dimmed" : ""
                }`}
                key={node.id}
                onClick={() => onSelect(node.id)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect(node.id);
                  }
                }}
                role="button"
                tabIndex={0}
                transform={`translate(${node.x} ${node.y})`}
              >
                {selected && (
                  <circle
                    className="node-selection-ring"
                    fill="none"
                    r={radius + 8}
                    stroke={nodeColors[node.kind]}
                  />
                )}
                <circle
                  className="node-body"
                  fill={`${nodeColors[node.kind]}18`}
                  filter={selected ? "url(#selected-glow)" : "url(#node-shadow)"}
                  r={radius}
                  stroke={nodeColors[node.kind]}
                />
                <text
                  className="node-glyph"
                  fill={nodeColors[node.kind]}
                  textAnchor="middle"
                  y="4"
                >
                  {nodeGlyphs[node.kind]}
                </text>
                <text className="node-title" textAnchor="middle" y={radius + 18}>
                  {node.label}
                </text>
                <text className="node-kind" textAnchor="middle" y={radius + 33}>
                  {node.kind}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}
