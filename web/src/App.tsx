import { useEffect, useMemo, useRef, useState } from "react";

import { fetchWorkspaceGraph } from "./api";
import { ACTIVITIES, DEMO_EDGES, DEMO_NODES } from "./data";
import GraphCanvas from "./GraphCanvas";
import Icon from "./Icon";
import type { EntityFilter, GraphNode } from "./types";

type ApiState = "checking" | "available" | "unavailable";

const filters: EntityFilter[] = ["All", "Incident", "Asset", "IOC", "Technique"];

const filterLabels: Record<EntityFilter, string> = {
  All: "All entities",
  Incident: "Incidents",
  Asset: "Assets",
  IOC: "IOCs",
  Technique: "Techniques",
};

function nodeMatchesFilter(node: GraphNode, filter: EntityFilter): boolean {
  if (filter === "All") return true;
  if (filter === "Incident") return node.kind === "Incident" || node.kind === "Alert";
  if (filter === "Asset")
    return ["Asset", "Identity", "Process"].includes(node.kind);
  if (filter === "Technique") return node.kind === "AttackTechnique";
  return [
    "IPAddress",
    "Domain",
    "URL",
    "Hash",
    "File",
    "Malware",
    "ThreatActor",
    "Campaign",
    "Vulnerability",
    "DataSource",
  ].includes(node.kind);
}

async function checkApi(signal: AbortSignal): Promise<boolean> {
  try {
    const response = await fetch("/api/v1/health/live", { signal });
    return response.ok;
  } catch {
    return false;
  }
}

function riskLabel(risk: GraphNode["risk"]): string {
  return risk.charAt(0).toUpperCase() + risk.slice(1);
}

function timeRangeLabel(hours: number): string {
  if (hours === 1) return "Last hour";
  if (hours < 24) return `Last ${hours} hours`;
  if (hours === 24) return "Last 24 hours";
  return `Last ${Math.round(hours / 24)} days`;
}

export default function App() {
  const initialParams = useMemo(
    () => new URLSearchParams(window.location.search),
    [],
  );
  const [apiState, setApiState] = useState<ApiState>("checking");
  const [graphNodes, setGraphNodes] = useState(DEMO_NODES);
  const [graphEdges, setGraphEdges] = useState(DEMO_EDGES);
  const [totalEntityCount, setTotalEntityCount] = useState(2847);
  const [dataMode, setDataMode] = useState<"demo" | "live">("demo");
  const [selectedId, setSelectedId] = useState(
    initialParams.get("entity") ?? "incident-1042",
  );
  const [entityFilter, setEntityFilter] = useState<EntityFilter>("All");
  const [query, setQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [criticalOnly, setCriticalOnly] = useState(
    initialParams.get("view") === "critical",
  );
  const [timeRange, setTimeRange] = useState(24);
  const [zoom, setZoom] = useState(1);
  const [toast, setToast] = useState("");
  const toastTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    const controller = new AbortController();
    const workspaceId =
      initialParams.get("workspace") ?? import.meta.env.VITE_WORKSPACE_ID;
    void checkApi(controller.signal).then(async (available) => {
      if (!controller.signal.aborted) {
        setApiState(available ? "available" : "unavailable");
      }
      if (available && workspaceId) {
        try {
          const liveGraph = await fetchWorkspaceGraph(workspaceId, controller.signal);
          if (!controller.signal.aborted && liveGraph.nodes.length) {
            setGraphNodes(liveGraph.nodes);
            setGraphEdges(liveGraph.edges);
            setTotalEntityCount(liveGraph.totalNodes);
            setSelectedId(liveGraph.nodes[0].id);
            setDataMode("live");
          }
        } catch {
          if (!controller.signal.aborted) setDataMode("demo");
        }
      }
    });
    return () => controller.abort();
  }, [initialParams]);

  useEffect(
    () => () => {
      if (toastTimer.current) window.clearTimeout(toastTimer.current);
    },
    [],
  );

  const visibleNodes = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return graphNodes.filter((node) => {
      const matchesTime = node.observedAgo <= timeRange;
      const matchesType = nodeMatchesFilter(node, entityFilter);
      const matchesQuery =
        !normalizedQuery ||
        [node.label, node.detail, node.kind, ...Object.values(node.properties)]
          .join(" ")
          .toLowerCase()
          .includes(normalizedQuery);
      return matchesTime && matchesType && matchesQuery;
    });
  }, [entityFilter, graphNodes, query, timeRange]);

  const visibleIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);
  const visibleEdges = useMemo(
    () =>
      graphEdges.filter(
        (edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target),
      ),
    [graphEdges, visibleIds],
  );

  const selectedNode =
    graphNodes.find((node) => node.id === selectedId) ?? graphNodes[0];
  const relatedEdges = graphEdges.filter(
    (edge) => edge.source === selectedNode.id || edge.target === selectedNode.id,
  );
  const searchResults = graphNodes.filter((node) =>
    [node.label, node.detail, node.kind]
      .join(" ")
      .toLowerCase()
      .includes(query.trim().toLowerCase()),
  ).slice(0, 5);
  const incidentCount =
    dataMode === "live"
      ? graphNodes.filter((node) => ["Incident", "Alert"].includes(node.kind)).length
      : 12;
  const criticalIncidentCount =
    dataMode === "live"
      ? graphNodes.filter(
          (node) =>
            ["Incident", "Alert"].includes(node.kind) && node.risk === "critical",
        ).length
      : 4;
  const highRiskIocCount =
    dataMode === "live"
      ? graphNodes.filter(
          (node) =>
            nodeMatchesFilter(node, "IOC") &&
            (node.risk === "critical" || node.risk === "high"),
        ).length
      : 38;

  const showToast = (message: string) => {
    setToast(message);
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(""), 2800);
  };

  const exportGraph = () => {
    const content = JSON.stringify(
      {
        exported_at: new Date().toISOString(),
        workspace: dataMode === "live" ? "live" : "demo",
        nodes: visibleNodes,
        relationships: visibleEdges,
      },
      null,
      2,
    );
    const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "threatgraph-export.json";
    anchor.click();
    URL.revokeObjectURL(url);
    showToast(`${visibleNodes.length} entities exported as JSON`);
  };

  const selectSearchResult = (node: GraphNode) => {
    setSelectedId(node.id);
    setQuery("");
    setEntityFilter("All");
    setTimeRange(Math.max(24, node.observedAgo));
    setSearchOpen(false);
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" aria-label="ThreatGraph home">
          <span className="brand-mark" aria-hidden="true">
            <i />
            <i />
            <i />
            <i />
          </span>
          <span>
            <strong>ThreatGraph</strong>
            <small>Intelligence platform</small>
          </span>
        </a>

        <nav className="primary-nav" aria-label="Primary navigation">
          <p className="nav-label">Workspace</p>
          <a className="nav-item" href="#overview">
            <Icon name="grid" />
            Overview
          </a>
          <a className="nav-item nav-item--active" href="#graph">
            <Icon name="graph" />
            Graph explorer
            <span className="nav-pulse" />
          </a>
          <a className="nav-item" href="#activity">
            <Icon name="alert" />
            Incidents
            <span className="nav-count">12</span>
          </a>
          <a className="nav-item" href="#intelligence">
            <Icon name="target" />
            Intelligence
          </a>

          <p className="nav-label nav-label--spaced">Manage</p>
          <button className="nav-item" type="button" onClick={() => showToast("Data sources are healthy")}>
            <Icon name="database" />
            Data sources
            <span className="nav-health" title="All sources healthy" />
          </button>
          <button className="nav-item" type="button" onClick={() => showToast("Workspace settings opened")}>
            <Icon name="settings" />
            Settings
          </button>
        </nav>

        <div className="sidebar-footer">
          <button className="workspace-card" type="button" onClick={() => showToast("Production workspace selected")}>
            <span className="workspace-avatar">P</span>
            <span>
              <strong>Production</strong>
              <small>AI Security Lab</small>
            </span>
            <Icon name="chevron" size={14} />
          </button>
          <p>v0.1.0 · {dataMode === "live" ? "Live workspace" : "Demo dataset"}</p>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="search-wrap">
            <Icon name="search" />
            <input
              aria-label="Search threat graph"
              onChange={(event) => {
                setQuery(event.target.value);
                setSearchOpen(true);
              }}
              onFocus={() => setSearchOpen(true)}
              placeholder="Search IP, domain, asset, technique…"
              value={query}
            />
            <kbd>⌘ K</kbd>
            {searchOpen && query.trim() && (
              <div className="search-results">
                <div className="search-results__label">Entities</div>
                {searchResults.length ? (
                  searchResults.map((node) => (
                    <button key={node.id} onClick={() => selectSearchResult(node)} type="button">
                      <span className={`entity-icon entity-icon--${node.kind.toLowerCase()}`}>
                        {node.kind === "IPAddress" ? "IP" : node.kind.slice(0, 1)}
                      </span>
                      <span>
                        <strong>{node.label}</strong>
                        <small>{node.detail}</small>
                      </span>
                      <em>{node.kind}</em>
                    </button>
                  ))
                ) : (
                  <p className="search-empty">No matching entities</p>
                )}
              </div>
            )}
          </div>
          <div className="topbar-actions">
            <div
              className={`api-status api-status--${apiState}`}
              role="status"
              title="FastAPI liveness status"
            >
              <i />
              {apiState === "available"
                ? dataMode === "live"
                  ? "Live data"
                  : "API connected"
                : apiState === "checking"
                  ? "Checking API"
                  : "Demo mode"}
            </div>
            <button aria-label="Help" className="icon-button" type="button" onClick={() => showToast("Documentation is available in /docs")}>
              <Icon name="help" />
            </button>
            <button aria-label="Notifications" className="icon-button notification-button" type="button" onClick={() => showToast("3 new intelligence updates")}>
              <Icon name="bell" />
              <span />
            </button>
            <button className="user-avatar" type="button" aria-label="Open user menu">MK</button>
          </div>
        </header>

        <div className="dashboard">
          <section className="page-heading" id="overview" aria-labelledby="page-title">
            <div>
              <div className="breadcrumb">
                <span>Production</span>
                <Icon name="chevron" size={12} />
                <span>Graph explorer</span>
              </div>
              <h1 id="page-title">Threat landscape</h1>
              <p>Trace entities, relationships, and evidence across your security workspace.</p>
            </div>
            <div className="heading-actions">
              <button className="button button--secondary" onClick={exportGraph} type="button">
                <Icon name="download" size={16} />
                Export graph
              </button>
              <button
                className="button button--primary"
                onClick={() => {
                  setSelectedId("incident-1042");
                  setEntityFilter("All");
                  setTimeRange(24);
                  setCriticalOnly(true);
                  showToast("Critical incident path focused");
                }}
                type="button"
              >
                <Icon name="bolt" size={16} />
                Investigate critical path
              </button>
            </div>
          </section>

          <section className="metric-grid" aria-label="Workspace metrics">
            <article className="metric-card">
              <div className="metric-icon metric-icon--blue"><Icon name="graph" /></div>
              <div>
                <span>Total entities</span>
                <strong>{totalEntityCount.toLocaleString()}</strong>
                <small><b>+12.4%</b> from last week</small>
              </div>
              <svg aria-hidden="true" className="sparkline" viewBox="0 0 82 34">
                <path d="M2 29 14 25 25 27 36 17 47 20 59 8 70 12 80 3" />
              </svg>
            </article>
            <article className="metric-card">
              <div className="metric-icon metric-icon--red"><Icon name="alert" /></div>
              <div>
                <span>Active incidents</span>
                <strong>{incidentCount}</strong>
                <small><b className="metric-up">{criticalIncidentCount} critical</b> require attention</small>
              </div>
              <div className="metric-stack" aria-hidden="true"><i /><i /><i /><i /><i /></div>
            </article>
            <article className="metric-card">
              <div className="metric-icon metric-icon--purple"><Icon name="target" /></div>
              <div>
                <span>High-risk IOCs</span>
                <strong>{highRiskIocCount}</strong>
                <small><b>7 new</b> in the last 24h</small>
              </div>
              <span className="metric-donut" aria-hidden="true">82%</span>
            </article>
            <article className="metric-card">
              <div className="metric-icon metric-icon--green"><Icon name="evidence" /></div>
              <div>
                <span>Evidence coverage</span>
                <strong>100%</strong>
                <small>All relationships grounded</small>
              </div>
              <div className="metric-check"><Icon name="shield" size={18} /></div>
            </article>
          </section>

          <section className="explorer-layout" id="graph">
            <article className="panel graph-panel">
              <header className="panel-header">
                <div>
                  <span className="panel-kicker">Live investigation</span>
                  <h2>Relationship graph</h2>
                </div>
                <div className="graph-summary">
                  <span><b>{visibleNodes.length}</b> visible entities</span>
                  <i />
                  <span><b>{visibleEdges.length}</b> relationships</span>
                </div>
              </header>

              <div className="filterbar">
                <div className="filter-tabs" aria-label="Filter by entity type">
                  {filters.map((filter) => (
                    <button
                      aria-pressed={entityFilter === filter}
                      className={entityFilter === filter ? "active" : ""}
                      key={filter}
                      onClick={() => setEntityFilter(filter)}
                      type="button"
                    >
                      {filterLabels[filter]}
                    </button>
                  ))}
                </div>
                <button
                  aria-pressed={criticalOnly}
                  className={`critical-toggle ${criticalOnly ? "active" : ""}`}
                  onClick={() => setCriticalOnly((current) => !current)}
                  type="button"
                >
                  <Icon name="filter" size={14} />
                  Critical path
                </button>
              </div>

              {visibleNodes.length ? (
                <GraphCanvas
                  criticalOnly={criticalOnly}
                  edges={visibleEdges}
                  nodes={visibleNodes}
                  onSelect={setSelectedId}
                  onZoomChange={setZoom}
                  selectedId={selectedId}
                  zoom={zoom}
                />
              ) : (
                <div className="graph-empty">
                  <Icon name="search" size={28} />
                  <strong>No entities in this view</strong>
                  <p>Broaden the time range or clear your search to continue.</p>
                  <button
                    onClick={() => {
                      setQuery("");
                      setEntityFilter("All");
                      setTimeRange(72);
                    }}
                    type="button"
                  >
                    Reset filters
                  </button>
                </div>
              )}

              <div className="timeline">
                <div className="timeline-heading">
                  <span><Icon name="clock" size={14} /> Observation window</span>
                  <strong>{timeRangeLabel(timeRange)}</strong>
                </div>
                <div className="range-wrap">
                  <span>1h</span>
                  <input
                    aria-label="Observation window in hours"
                    max="72"
                    min="1"
                    onChange={(event) => setTimeRange(Number(event.target.value))}
                    style={{ "--range-progress": `${((timeRange - 1) / 71) * 100}%` } as React.CSSProperties}
                    type="range"
                    value={timeRange}
                  />
                  <span>72h</span>
                </div>
                <div className="timeline-ticks" aria-hidden="true">
                  <i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i />
                </div>
              </div>
            </article>

            <aside className="panel inspector-panel" id="intelligence" aria-label="Selected entity details">
              <header className="inspector-header">
                <div className={`entity-badge entity-badge--${selectedNode.risk}`}>
                  {selectedNode.kind === "Incident" ? "!" : selectedNode.kind.slice(0, 2).toUpperCase()}
                </div>
                <div>
                  <span>{selectedNode.kind}</span>
                  <h2>{selectedNode.label}</h2>
                  <p>{selectedNode.detail}</p>
                </div>
                <span className={`risk-badge risk-badge--${selectedNode.risk}`}>
                  {riskLabel(selectedNode.risk)}
                </span>
              </header>

              <div className="confidence">
                <span>Confidence</span>
                <strong>{selectedNode.confidence}%</strong>
                <div><i style={{ width: `${selectedNode.confidence}%` }} /></div>
              </div>

              <section className="detail-section">
                <h3>Entity properties</h3>
                <dl>
                  {Object.entries(selectedNode.properties).map(([name, value]) => (
                    <div key={name}>
                      <dt>{name}</dt>
                      <dd>{value}</dd>
                    </div>
                  ))}
                </dl>
              </section>

              <section className="detail-section">
                <div className="detail-title-row">
                  <h3>Relationships</h3>
                  <span>{relatedEdges.length}</span>
                </div>
                <div className="relationship-list">
                  {relatedEdges.slice(0, 4).map((edge) => {
                    const otherId = edge.source === selectedNode.id ? edge.target : edge.source;
                    const other = graphNodes.find((node) => node.id === otherId);
                    if (!other) return null;
                    return (
                      <button key={edge.id} onClick={() => setSelectedId(other.id)} type="button">
                        <i className={`relationship-dot relationship-dot--${other.risk}`} />
                        <span>
                          <strong>{other.label}</strong>
                          <small>{edge.label.replaceAll("_", " ")}</small>
                        </span>
                        <em>{edge.confidence}%</em>
                        <Icon name="chevron" size={13} />
                      </button>
                    );
                  })}
                </div>
              </section>

              <section className="evidence-card">
                <div className="evidence-title">
                  <span><Icon name="evidence" size={16} /></span>
                  <div>
                    <h3>Grounded evidence</h3>
                    <small>Verified source</small>
                  </div>
                  <Icon name="shield" className="verified-icon" size={18} />
                </div>
                <p>{selectedNode.evidence.description}</p>
                <dl>
                  <div><dt>Source</dt><dd>{selectedNode.evidence.source}</dd></div>
                  <div><dt>Observed</dt><dd>{selectedNode.evidence.observedAt}</dd></div>
                </dl>
              </section>
            </aside>
          </section>

          <section className="panel activity-panel" id="activity">
            <header className="panel-header">
              <div>
                <span className="panel-kicker">Audit trail</span>
                <h2>Recent intelligence activity</h2>
              </div>
              <button type="button" onClick={() => showToast("Showing the latest intelligence events")}>
                View all activity
                <Icon name="chevron" size={13} />
              </button>
            </header>
            <div className="activity-table" role="table" aria-label="Recent intelligence activity">
              <div className="activity-table__head" role="row">
                <span role="columnheader">Event</span>
                <span role="columnheader">Source</span>
                <span role="columnheader">Severity</span>
                <span role="columnheader">Time</span>
              </div>
              {ACTIVITIES.map((activity) => (
                <div className="activity-row" key={activity.id} role="row">
                  <span className={`activity-symbol activity-symbol--${activity.severity}`}>
                    <Icon name={activity.severity === "critical" ? "bolt" : "activity"} size={16} />
                  </span>
                  <span className="activity-event" role="cell">
                    <strong>{activity.title}</strong>
                    <small>{activity.detail}</small>
                  </span>
                  <span className="activity-source" role="cell">{activity.source}</span>
                  <span role="cell"><i className={`severity-dot severity-dot--${activity.severity}`} />{riskLabel(activity.severity)}</span>
                  <time role="cell">{activity.time}</time>
                </div>
              ))}
            </div>
          </section>
        </div>
      </main>

      {toast && (
        <div className="toast" role="status">
          <span><Icon name="shield" size={15} /></span>
          {toast}
        </div>
      )}
    </div>
  );
}
