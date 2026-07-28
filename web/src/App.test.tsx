import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import App from "./App";

describe("ThreatGraph dashboard", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders the graph workspace and reports a healthy API", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }));

    render(<App />);

    expect(screen.getByRole("heading", { name: "Threat landscape" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Relationship graph" })).toBeInTheDocument();
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
});
