export type NodeKind =
  | "Incident"
  | "Asset"
  | "IPAddress"
  | "Domain"
  | "File"
  | "Malware"
  | "ThreatActor"
  | "AttackTechnique"
  | "Identity"
  | "Process"
  | "URL"
  | "Hash"
  | "Vulnerability"
  | "Alert"
  | "Campaign"
  | "DataSource";

export type RiskLevel = "critical" | "high" | "medium" | "low";

export type GraphNode = {
  id: string;
  label: string;
  detail: string;
  kind: NodeKind;
  risk: RiskLevel;
  x: number;
  y: number;
  observedAgo: number;
  confidence: number;
  properties: Record<string, string>;
  evidence: {
    source: string;
    observedAt: string;
    description: string;
  };
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  label: string;
  confidence: number;
  critical?: boolean;
};

export type Activity = {
  id: string;
  title: string;
  detail: string;
  time: string;
  severity: RiskLevel;
  source: string;
};

export type EntityFilter = "All" | "Incident" | "Asset" | "IOC" | "Technique";
