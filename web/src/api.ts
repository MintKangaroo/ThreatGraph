import type { GraphEdge, GraphNode, NodeKind, RiskLevel } from "./types";

type ApiEntity = {
  id: string;
  entity_type: string;
  key: string;
  name: string | null;
  sensitive: boolean;
  properties: Record<string, string | number | boolean | string[] | number[]>;
};

type ApiRelationship = {
  id: string;
  relationship_type: string;
  source_entity_id: string;
  target_entity_id: string;
  confidence: number;
  source: string;
  last_seen: string;
};

type ApiGraphPage = {
  nodes: ApiEntity[];
  relationships: ApiRelationship[];
  total_nodes: number;
};

const supportedKinds = new Set<NodeKind>([
  "Incident",
  "Asset",
  "IPAddress",
  "Domain",
  "File",
  "Malware",
  "ThreatActor",
  "AttackTechnique",
  "Identity",
  "Process",
  "URL",
  "Hash",
  "Vulnerability",
  "Alert",
  "Campaign",
  "DataSource",
]);

function riskFromProperties(properties: ApiEntity["properties"]): RiskLevel {
  const value = String(properties.severity ?? properties.risk ?? "").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(value)
    ? (value as RiskLevel)
    : "low";
}

function displayProperties(
  properties: ApiEntity["properties"],
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(properties)
      .slice(0, 6)
      .map(([key, value]) => [key, Array.isArray(value) ? value.join(", ") : String(value)]),
  );
}

function layout(index: number, total: number): { x: number; y: number } {
  if (total === 1) return { x: 450, y: 250 };
  const angle = (index / total) * Math.PI * 2 - Math.PI / 2;
  const ring = index % 3 === 0 ? 145 : 205;
  return {
    x: 450 + Math.cos(angle) * ring,
    y: 250 + Math.sin(angle) * ring * 0.78,
  };
}

export async function fetchWorkspaceGraph(
  workspaceId: string,
  signal: AbortSignal,
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[]; totalNodes: number }> {
  const response = await fetch(
    `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/graph?limit=100`,
    { signal },
  );
  if (!response.ok) throw new Error("graph query failed");
  const page = (await response.json()) as ApiGraphPage;
  const nodes = page.nodes
    .filter((node) => supportedKinds.has(node.entity_type as NodeKind))
    .map((node, index, collection): GraphNode => {
      const position = layout(index, collection.length);
      const rawConfidence = Number(node.properties.confidence ?? 80);
      return {
        id: node.id,
        label: node.name ?? node.key,
        detail: node.sensitive ? "Sensitive value masked" : node.key,
        kind: node.entity_type as NodeKind,
        risk: riskFromProperties(node.properties),
        x: position.x,
        y: position.y,
        observedAgo: 1,
        confidence: Math.round(rawConfidence <= 1 ? rawConfidence * 100 : rawConfidence),
        properties: displayProperties(node.properties),
        evidence: {
          source: String(node.properties.source ?? "Neo4j workspace graph"),
          observedAt: String(node.properties.observed_at ?? "Loaded from live workspace"),
          description: "Entity loaded from the workspace-scoped ThreatGraph query API.",
        },
      };
    });
  const visibleIds = new Set(nodes.map((node) => node.id));
  const edges = page.relationships
    .filter(
      (relationship) =>
        visibleIds.has(relationship.source_entity_id) &&
        visibleIds.has(relationship.target_entity_id),
    )
    .map(
      (relationship): GraphEdge => ({
        id: relationship.id,
        source: relationship.source_entity_id,
        target: relationship.target_entity_id,
        label: relationship.relationship_type,
        confidence: Math.round(relationship.confidence * 100),
      }),
    );
  return { nodes, edges, totalNodes: page.total_nodes };
}
