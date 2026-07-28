import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchWorkspaceGraph } from "./api";

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
});
