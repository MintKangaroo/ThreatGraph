import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import App from "./App";

describe("App", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("shows the platform foundation and a healthy API", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }));

    render(<App />);

    expect(screen.getByRole("heading", { name: "ThreatGraph" })).toBeInTheDocument();
    expect(screen.getByText("Neo4j graph store")).toBeInTheDocument();
    expect(await screen.findByText("API available")).toBeInTheDocument();
  });

  it("reports an unavailable API without replacing the shell", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));

    render(<App />);

    await waitFor(() => expect(screen.getByText("API unavailable")).toBeInTheDocument());
    expect(screen.getByText("Platform foundation")).toBeInTheDocument();
  });
});
