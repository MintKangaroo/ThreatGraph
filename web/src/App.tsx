import { useEffect, useState } from "react";

type ApiState = "checking" | "available" | "unavailable";

async function checkApi(signal: AbortSignal): Promise<boolean> {
  try {
    const response = await fetch("/api/v1/health/live", { signal });
    return response.ok;
  } catch {
    return false;
  }
}

export default function App() {
  const [apiState, setApiState] = useState<ApiState>("checking");

  useEffect(() => {
    const controller = new AbortController();
    void checkApi(controller.signal).then((available) => {
      if (!controller.signal.aborted) {
        setApiState(available ? "available" : "unavailable");
      }
    });
    return () => controller.abort();
  }, []);

  return (
    <main className="shell">
      <section className="hero" aria-labelledby="page-title">
        <div className="eyebrow">Threat Intelligence Graph</div>
        <h1 id="page-title">ThreatGraph</h1>
        <p className="summary">
          Shared correlation infrastructure for AI-SOC Dashboard, AutoPentest AI, and
          SentinelFlow.
        </p>
        <div className={`status status--${apiState}`} role="status">
          <span className="status__dot" aria-hidden="true" />
          API {apiState}
        </div>
      </section>

      <section className="foundation" aria-label="Foundation services">
        <h2>Platform foundation</h2>
        <ul>
          <li>PostgreSQL metadata store</li>
          <li>Neo4j graph store</li>
          <li>Redis and Celery task runtime</li>
        </ul>
        <p>The interactive graph explorer will arrive in the visualization milestone.</p>
      </section>
    </main>
  );
}
