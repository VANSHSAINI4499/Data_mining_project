import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll } from "vitest";

import { setCsrfToken } from "../api/client";
import { server } from "./server";

beforeAll(async () => {
  server.listen({ onUnhandledFrame: "error" });
  // Routes are lazy-loaded (code splitting). Import the page modules once up front so a
  // test's first render does not wait for module transformation inside a findBy timeout.
  await Promise.all([
    import("../pages/AdminPages"),
    import("../pages/EventPages"),
    import("../pages/IngestionPages"),
    import("../pages/InvestigationPages"),
    import("../pages/MlPages"),
    import("../pages/OverviewPage"),
    import("../pages/ThreatIntelPages"),
  ]);
}, 60_000);
afterEach(() => {
  cleanup();
  server.resetHandlers();
  setCsrfToken(null);
});
afterAll(() => server.close());
