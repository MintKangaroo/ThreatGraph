import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import App from "./App";

describe("ThreatGraph dashboard", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    window.history.replaceState({}, "", "/");
  });

  it("renders the graph workspace and reports a healthy API", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }));

    render(<App />);

    expect(screen.getByRole("heading", { name: "Threat landscape" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Relationship graph" })).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Credential theft infrastructure chain" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Evidence grounded")).toBeInTheDocument();
    expect(screen.getByText("Grounded evidence")).toBeInTheDocument();
    expect(await screen.findByText("API connected")).toBeInTheDocument();
  });

  it("keeps the interactive demo available while the API is offline", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));

    render(<App />);

    await waitFor(() => expect(screen.getByText("Demo mode")).toBeInTheDocument());
    expect(screen.getByRole("img", { name: /Threat graph with/ })).toBeInTheDocument();
    expect(screen.getByText("INC-1042", { selector: "h2" })).toBeInTheDocument();
  });

  it("filters entity types and updates the evidence inspector from the graph", () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }));
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "IPAddress: 185.220.101.17" }));
    expect(
      screen.getByRole("heading", { name: "185.220.101.17" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Network detection")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Incidents" }));
    expect(
      screen.getByRole("img", { name: "Threat graph with 1 visible entities" }),
    ).toBeInTheDocument();
  });

  it("finds and focuses an entity with the global search", () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }));
    render(<App />);

    fireEvent.change(screen.getByRole("textbox", { name: "Search threat graph" }), {
      target: { value: "StealC" },
    });
    fireEvent.click(screen.getByRole("button", { name: /StealC Infostealer family/ }));

    expect(screen.getByRole("heading", { name: "StealC" })).toBeInTheDocument();
    expect(screen.getByText("Threat intelligence feed")).toBeInTheDocument();
  });

  it("opens a shareable critical-path investigation deep link", () => {
    window.history.replaceState({}, "", "/?view=critical&entity=ip-c2");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }));

    render(<App />);

    expect(screen.getByRole("button", { name: "Critical path" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(
      screen.getByRole("heading", { name: "185.220.101.17" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Network detection")).toBeInTheDocument();
  });

  it("explains that server-side expansion requires a live workspace", () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }));
    render(<App />);

    fireEvent.doubleClick(
      screen.getByRole("button", { name: "Incident: INC-1042" }),
    );

    expect(
      screen.getByText("Connect a workspace to expand the server-side neighborhood"),
    ).toBeInTheDocument();
  });

  it("loads live correlations and expands a server-side neighborhood", async () => {
    const workspaceId = "00000000-0000-4000-8000-000000000001";
    const incidentId = "00000000-0000-4000-8000-000000000002";
    window.history.replaceState({}, "", `/?workspace=${workspaceId}`);
    const graphPage = {
      nodes: [
        {
          id: incidentId,
          entity_type: "Incident",
          key: "incident-live",
          name: "INC-LIVE",
          sensitive: false,
          properties: { severity: "high", confidence: 0.92 },
        },
      ],
      relationships: [],
      total_nodes: 1,
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: true })
      .mockResolvedValueOnce({ ok: true, json: async () => graphPage })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          report: {
            window_start: "2026-07-28T00:00:00Z",
            window_end: "2026-07-29T00:00:00Z",
            scanned_entities: 1,
            scanned_relationships: 0,
            findings: [
              {
                id: "finding-live",
                kind: "shared_context",
                severity: "high",
              },
            ],
          },
          narratives: [
            {
              finding_id: "finding-live",
              title: "Live workspace correlation",
              summary: "The live graph produced an evidence-backed finding.",
              claims: [],
              gaps: ["Analyst validation required."],
              grounded: false,
            },
          ],
          truncated: false,
        }),
      })
      .mockResolvedValueOnce({ ok: true, json: async () => graphPage });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByText("Live data")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Live workspace correlation" }),
    ).toBeInTheDocument();
    fireEvent.doubleClick(
      screen.getByRole("button", { name: "Incident: INC-LIVE" }),
    );
    expect(
      await screen.findByText("Expanded 1 entities across 2 graph hops"),
    ).toBeInTheDocument();
    expect(fetchMock).toHaveBeenLastCalledWith(
      `/api/v1/workspaces/${workspaceId}/graph/entities/${incidentId}/neighborhood?depth=2&limit=100`,
      expect.any(Object),
    );
  });
});
