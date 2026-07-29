import { afterEach, describe, expect, it, vi } from "vitest";

import {
  fetchEntityNeighborhood,
  fetchWorkspaceAnalysis,
  fetchWorkspaceGraph,
} from "./api";

describe("workspace graph API adapter", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("maps supported entities and relationships into dashboard data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          nodes: [
            {
              id: "node-1",
              entity_type: "Incident",
              key: "incident-1",
              name: "INC-1",
              sensitive: false,
              properties: { severity: "critical", confidence: 0.96 },
            },
            {
              id: "node-2",
              entity_type: "Evidence",
              key: "evidence-1",
              name: null,
              sensitive: false,
              properties: {},
            },
            {
              id: "node-3",
              entity_type: "Asset",
              key: "asset-1",
              name: "Endpoint 1",
              sensitive: false,
              properties: { os: "Linux" },
            },
          ],
          relationships: [
            {
              id: "relationship-1",
              relationship_type: "observed_on",
              source_entity_id: "node-1",
              target_entity_id: "node-3",
              confidence: 0.91,
              source: "test",
              last_seen: "2026-07-28T00:00:00Z",
            },
          ],
          total_nodes: 3,
        }),
      }),
    );

    const graph = await fetchWorkspaceGraph("workspace-1", new AbortController().signal);

    expect(graph.nodes).toHaveLength(2);
    expect(graph.nodes[0]).toMatchObject({
      label: "INC-1",
      kind: "Incident",
      risk: "critical",
      confidence: 96,
    });
    expect(graph.edges[0]).toMatchObject({
      label: "observed_on",
      confidence: 91,
    });
    expect(graph.totalNodes).toBe(3);
  });

  it("rejects unsuccessful graph responses", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false }));

    await expect(
      fetchWorkspaceGraph("workspace-1", new AbortController().signal),
    ).rejects.toThrow("graph query failed");
  });

  it("loads a bounded entity neighborhood through the same graph mapper", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        nodes: [
          {
            id: "node-1",
            entity_type: "Asset",
            key: "asset-1",
            name: "Endpoint 1",
            sensitive: false,
            properties: { risk: "high" },
          },
        ],
        relationships: [],
        total_nodes: 1,
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const graph = await fetchEntityNeighborhood(
      "workspace/1",
      "entity/1",
      new AbortController().signal,
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/workspaces/workspace%2F1/graph/entities/entity%2F1/neighborhood?depth=2&limit=100",
      expect.any(Object),
    );
    expect(graph.nodes[0]).toMatchObject({ label: "Endpoint 1", risk: "high" });
  });

  it("maps correlation findings and grounded claims for the dashboard", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          report: {
            window_start: "2026-07-28T00:00:00Z",
            window_end: "2026-07-29T00:00:00Z",
            scanned_entities: 4,
            scanned_relationships: 3,
            findings: [
              {
                id: "finding-1",
                kind: "shared_indicator",
                severity: "high",
              },
            ],
          },
          narratives: [
            {
              finding_id: "finding-1",
              title: "Shared IP address",
              summary: "Two incidents share one observed IP.",
              claims: [
                {
                  text: "Incident A communicates with 192.0.2.10.",
                  relationship_id: "relationship-1",
                  evidence_id: "evidence-1",
                  confidence: 0.94,
                },
              ],
              gaps: [],
              grounded: true,
            },
          ],
          truncated: false,
        }),
      }),
    );

    const analysis = await fetchWorkspaceAnalysis(
      "workspace-1",
      new AbortController().signal,
    );

    expect(analysis.narratives[0]).toMatchObject({
      findingId: "finding-1",
      kind: "shared_indicator",
      severity: "high",
      grounded: true,
    });
    expect(analysis.narratives[0].claims[0].confidence).toBe(94);
    expect(analysis.scannedEntities).toBe(4);
  });

  it("rejects unsuccessful analysis responses", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false }));

    await expect(
      fetchWorkspaceAnalysis("workspace-1", new AbortController().signal),
    ).rejects.toThrow("analysis query failed");
  });
});
