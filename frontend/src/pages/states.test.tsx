import { screen } from "@testing-library/react";
import { delay, http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { renderApp } from "../test/render";
import { API, emptyPage, problem, problemResponse, server, sessionFor } from "../test/server";

const EMPTY_DQ = { by_source: [], latest_failures: [] };

/** Each page, the endpoint that drives its main content, and that endpoint's empty body. */
const PAGES: {
  path: string;
  endpoint: string;
  empty: unknown;
  emptyText: string;
  others?: Record<string, unknown>;
}[] = [
  {
    path: "/ingestion",
    endpoint: "/ingestion/batches",
    empty: emptyPage,
    emptyText: "No ingestion batches yet",
    others: { "/sources": [], "/adapters": [] },
  },
  {
    path: "/events",
    endpoint: "/events",
    empty: emptyPage,
    emptyText: "No events match these filters in the selected range",
  },
  {
    path: "/classification",
    endpoint: "/classification/training-runs",
    empty: [],
    emptyText: "No training runs yet",
    others: { "/classification/summary": { model: null, predictions_by_category: [] } },
  },
  {
    path: "/anomalies",
    endpoint: "/anomalies",
    empty: emptyPage,
    emptyText: "No anomaly results in this range",
  },
  { path: "/alerts", endpoint: "/alerts", empty: emptyPage, emptyText: "No alerts in this range" },
  { path: "/cases", endpoint: "/cases", empty: [], emptyText: "No cases" },
  { path: "/models", endpoint: "/models", empty: [], emptyText: "No models registered yet" },
  {
    path: "/threat-intel?tab=indicators",
    endpoint: "/threat-intel/indicators",
    empty: emptyPage,
    emptyText: "No indicators",
  },
  {
    path: "/threat-intel?tab=matches",
    endpoint: "/threat-intel/matches",
    empty: emptyPage,
    emptyText: "No indicator matches",
  },
  {
    path: "/data-quality",
    endpoint: "/data-quality/summary",
    empty: EMPTY_DQ,
    emptyText: "No data-quality checks ran in this range",
  },
  {
    path: "/settings?tab=rules",
    endpoint: "/correlation/rules",
    empty: [],
    emptyText: "No correlation rules",
  },
];

function setup(page: (typeof PAGES)[number], main: Parameters<typeof http.get>[1]) {
  server.use(
    http.get(`${API}/auth/me`, () => HttpResponse.json(sessionFor("viewer"))),
    ...Object.entries(page.others ?? {}).map(([path, body]) =>
      http.get(`${API}${path}`, () => HttpResponse.json(body as object)),
    ),
    http.get(`${API}${page.endpoint}`, main),
  );
}

describe.each(PAGES)("$path", (page) => {
  it("shows a loading skeleton while waiting", async () => {
    setup(page, async () => {
      await delay("infinite");
      return HttpResponse.json(page.empty as object);
    });
    renderApp(page.path);
    expect((await screen.findAllByRole("status", { name: "Loading" })).length).toBeGreaterThan(0);
  });

  it("explains an empty result without showing numbers", async () => {
    setup(page, () => HttpResponse.json(page.empty as object));
    renderApp(page.path);
    const empty = await screen.findByText(page.emptyText);
    expect(empty).not.toHaveTextContent(/\d/);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("shows the problem detail and request ID on error", async () => {
    setup(page, () => problemResponse(problem(500, "Internal error", "query failed")));
    renderApp(page.path);
    expect(await screen.findByText("query failed")).toBeInTheDocument();
    expect(screen.getAllByText("req-test-1").length).toBeGreaterThan(0);
  });
});
