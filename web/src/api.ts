import type {
  GraphEdge,
  GraphNode,
  GroundedAnalysis,
  NodeKind,
  RiskLevel,
  WorkspaceAnalysis,
} from "./types";

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

type ApiAnalysisResponse = {
  report: {
    window_start: string;
    window_end: string;
    scanned_entities: number;
    scanned_relationships: number;
    findings: {
      id: string;
      kind: GroundedAnalysis["kind"];
      severity: GroundedAnalysis["severity"];
    }[];
  };
  narratives: {
    finding_id: string;
    title: string;
    summary: string;
    claims: {
      text: string;
      relationship_id: string;
      evidence_id: string;
      confidence: number;
    }[];
    gaps: string[];
    grounded: boolean;
  }[];
  truncated: boolean;
};

export type DashboardGraph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  totalNodes: number;
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
): Promise<DashboardGraph> {
  const response = await fetch(
    `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/graph?limit=100`,
    { signal },
  );
  if (!response.ok) throw new Error("graph query failed");
  const page = (await response.json()) as ApiGraphPage;
  return mapGraphPage(page);
}

export async function fetchEntityNeighborhood(
  workspaceId: string,
  entityId: string,
  signal: AbortSignal,
  depth = 2,
): Promise<DashboardGraph> {
  const response = await fetch(
    `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/graph/entities/${encodeURIComponent(entityId)}/neighborhood?depth=${depth}&limit=100`,
    { signal },
  );
  if (!response.ok) throw new Error("neighborhood query failed");
  return mapGraphPage((await response.json()) as ApiGraphPage);
}

export async function fetchWorkspaceAnalysis(
  workspaceId: string,
  signal: AbortSignal,
  windowHours = 24,
): Promise<WorkspaceAnalysis> {
  const response = await fetch(
    `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/analysis/correlations?window_hours=${windowHours}`,
    { signal },
  );
  if (!response.ok) throw new Error("analysis query failed");
  const result = (await response.json()) as ApiAnalysisResponse;
  const findings = new Map(result.report.findings.map((finding) => [finding.id, finding]));
  return {
    narratives: result.narratives.map((narrative) => {
      const finding = findings.get(narrative.finding_id);
      return {
        findingId: narrative.finding_id,
        title: narrative.title,
        summary: narrative.summary,
        kind: finding?.kind ?? "shared_context",
        severity: finding?.severity ?? "medium",
        claims: narrative.claims.map((claim) => ({
          text: claim.text,
          relationshipId: claim.relationship_id,
          evidenceId: claim.evidence_id,
          confidence: Math.round(claim.confidence * 100),
        })),
        gaps: narrative.gaps,
        grounded: narrative.grounded,
      };
    }),
    scannedEntities: result.report.scanned_entities,
    scannedRelationships: result.report.scanned_relationships,
    windowStart: result.report.window_start,
    windowEnd: result.report.window_end,
    truncated: result.truncated,
  };
}

function mapGraphPage(page: ApiGraphPage): DashboardGraph {
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
