import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { renderApp } from "../test/render";
import {
  API,
  emptyOverview,
  emptyPage,
  problem,
  problemResponse,
  server,
  sessionFor,
} from "../test/server";

function loggedInAs(role: "viewer" | "analyst" | "admin") {
  server.use(http.get(`${API}/auth/me`, () => HttpResponse.json(sessionFor(role))));
}

const ALERT_ID = "b85efb4f-cff3-42ba-bdab-6dff514f356c";
const CASE_ID = "7d1b8b8e-5a8c-4a59-9d3c-0d2b9b0c1a11";

const alertDetail = (status: string) => ({
  alert_id: ALERT_ID,
  status,
  title: "Repeated authentication failures followed by a success: account svc-backup",
  primary_entity_type: "account",
  primary_entity_value: "svc-backup",
  risk_score: 25,
  severity: "medium",
  first_event_time: "2026-01-09T02:00:00Z",
  last_event_time: "2026-01-09T02:08:50Z",
  evidence_count: 26,
  case_id: null,
  related_alert_id: null,
  dismiss_reason: null,
  kind: "hypothesis",
  rule: {
    rule_key: "bruteforce_then_success",
    version: 1,
    name: "Repeated authentication failures followed by a success",
    description: "Many failed logins for one account then a success within the window.",
  },
  risk_breakdown: {
    base: 24.6,
    note: "transparent rule-based score (0-100); not a probability",
    asset: { asset_id: null, criticality: "unknown" },
    score: 25,
    severity: "medium",
    components: {
      classification: { max: 30, value: 0, inputs: null },
      anomaly: { max: 20, value: 0, inputs: null },
      threat_intel: { max: 30, value: 0, inputs: null },
      repetition: { max: 10, value: 4.7, inputs: { evidence_count: 26 } },
      rule_severity: { max: 10, value: 7.5, inputs: { base_severity: "high" } },
    },
    asset_multiplier: 1.0,
    risk_model_version: "risk_v1",
  },
  evidence: [
    {
      evidence_type: "event",
      category: "observed",
      evidence_ref: "812",
      event_id: "812",
      event_time: "2026-01-09T02:00:00Z",
      step_id: "failures",
      contribution: {},
    },
  ],
  feedback: [],
});

describe("overview with data", () => {
  it("shows stat cards and active models with the dataset named", async () => {
    loggedInAs("viewer");
    server.use(
      http.get(`${API}/dashboard/overview`, () =>
        HttpResponse.json({
          ...emptyOverview,
          events: { ...emptyOverview.events, is_empty: false, total: 1582, by_type: { auth: 136 } },
          ingestion: {
            ...emptyOverview.ingestion,
            is_empty: false,
            batches_by_status: { completed: 1 },
          },
          alerts: {
            ...emptyOverview.alerts,
            is_empty: false,
            open_total: 5,
            open_by_severity: { critical: 0, high: 0, medium: 2, low: 3 },
          },
          models: {
            ...emptyOverview.models,
            is_empty: false,
            active: [
              {
                model_id: "5aaa5418-6444-49fc-8b9a-e47785dfd93b",
                name: "attack_classifier",
                version: 1,
                task: "classification",
                algorithm: "random_forest",
                promoted_at: "2026-10-14T20:53:22Z",
                test_metrics: { macro_f1: 0.6619, weighted_f1: 0.9636, rows: 287 },
                evaluated_on: {
                  split: "held-out test split of the training snapshot",
                  datasets: ["Synthetic scenarios"],
                  snapshot_rows: 1435,
                },
              },
            ],
          },
        }),
      ),
    );
    renderApp("/");
    expect(await screen.findByText("1,582")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText(/Test macro-F1 0.662/)).toHaveTextContent("Synthetic scenarios");
    expect(screen.queryByText("No security analytics yet")).not.toBeInTheDocument();
  });

  it("keeps the page usable when the overview fails", async () => {
    loggedInAs("viewer");
    server.use(
      http.get(`${API}/dashboard/overview`, () =>
        problemResponse(problem(500, "Internal error", "database unavailable")),
      ),
    );
    renderApp("/");
    expect(await screen.findByText("database unavailable")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "System status" })).toBeInTheDocument();
    expect(screen.getByText("req-test-1")).toBeInTheDocument();
  });
});

describe("alert triage", () => {
  it("labels alerts as hypotheses and requires a reason to dismiss", async () => {
    loggedInAs("analyst");
    let patched: unknown = null;
    server.use(
      http.get(`${API}/alerts/${ALERT_ID}`, () => HttpResponse.json(alertDetail("acknowledged"))),
      http.patch(`${API}/alerts/${ALERT_ID}`, async ({ request }) => {
        patched = await request.json();
        return HttpResponse.json({ ...alertDetail("dismissed") });
      }),
    );
    renderApp(`/alerts/${ALERT_ID}`);
    expect(
      await screen.findByText("Alerts are hypotheses for review, not confirmed incidents."),
    ).toBeInTheDocument();
    expect(screen.getByText("risk_v1", { exact: false })).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Dismiss" }));
    const dialog = screen.getByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: "Confirm" });
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByLabelText("Reason"), "authorised scanner");
    await user.click(confirm);
    await waitFor(() =>
      expect(patched).toEqual({ status: "dismissed", dismiss_reason: "authorised scanner" }),
    );
  });

  it("hides triage actions from viewers", async () => {
    loggedInAs("viewer");
    server.use(http.get(`${API}/alerts/${ALERT_ID}`, () => HttpResponse.json(alertDetail("new"))));
    renderApp(`/alerts/${ALERT_ID}`);
    expect(await screen.findByText("Risk breakdown (risk_v1)")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Acknowledge" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "event 812" })).toHaveAttribute("href", "/events/812");
  });
});

describe("cases", () => {
  it("closes a case only with a disposition", async () => {
    loggedInAs("analyst");
    let body: unknown = null;
    const kase = {
      case_id: CASE_ID,
      title: "Brute force on svc-backup",
      status: "investigating",
      disposition: null,
      severity: "high",
      assigned_to: null,
      summary: null,
      opened_at: "2026-10-15T00:00:00Z",
      closed_at: null,
      confirmed_incident: false,
      alerts: [],
    };
    server.use(
      http.get(`${API}/cases/${CASE_ID}`, () => HttpResponse.json(kase)),
      http.get(`${API}/cases/${CASE_ID}/timeline`, () =>
        HttpResponse.json([
          {
            entry_id: 1,
            entry_time: "2026-10-15T00:00:00Z",
            entry_type: "status_change",
            body: "case opened",
            ref: {},
          },
        ]),
      ),
      http.patch(`${API}/cases/${CASE_ID}`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ ...kase, status: "closed" });
      }),
    );
    renderApp(`/cases/${CASE_ID}`);
    expect(await screen.findByText("case opened")).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Close case" }));
    const dialog = screen.getByRole("dialog");
    await user.selectOptions(within(dialog).getByLabelText("Disposition"), "false_positive");
    await user.click(within(dialog).getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(body).toEqual({ status: "closed", disposition: "false_positive" }));
  });
});

describe("threat intelligence", () => {
  it("explains that feeds are optional when none exist", async () => {
    loggedInAs("viewer");
    server.use(http.get(`${API}/threat-intel/feeds`, () => HttpResponse.json([])));
    renderApp("/threat-intel");
    expect(
      await screen.findByText("No feeds configured — the system works without them"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Import" })).not.toBeInTheDocument();
  });

  it("shows defanged indicator values", async () => {
    loggedInAs("viewer");
    server.use(
      http.get(`${API}/threat-intel/indicators`, () =>
        HttpResponse.json({
          ...emptyPage,
          items: [
            {
              indicator_id: 5,
              feed_key: "local-csv",
              feed_reliability: "C",
              indicator_type: "url",
              display_value: "hxxp://payload[.]example[.]test/a[.]bin",
              confidence: 50,
              tlp: "TLP:CLEAR",
              description: "Synthetic defanged URL",
              first_seen: "2025-12-02T00:00:00Z",
              last_seen: "2026-01-11T00:00:00Z",
              valid_from: "2025-12-02T00:00:00Z",
              valid_until: "2026-03-12T00:00:00Z",
              revoked: false,
              technique_ids: [],
              state: "expired",
              matchable: true,
            },
          ],
        }),
      ),
    );
    renderApp("/threat-intel?tab=indicators");
    expect(await screen.findByText("hxxp://payload[.]example[.]test/a[.]bin")).toBeInTheDocument();
    expect(screen.queryByText("http://payload.example.test/a.bin")).not.toBeInTheDocument();
  });
});

describe("models and classification", () => {
  it("shows the promotion gate problems returned by the API", async () => {
    loggedInAs("admin");
    const id = "7ce04201-2e44-4800-a17e-1650267ca348";
    server.use(
      http.get(`${API}/models/${id}`, () =>
        HttpResponse.json({
          model_id: id,
          name: "attack_classifier",
          version: 2,
          task: "classification",
          algorithm: "random_forest",
          status: "candidate",
          training_run_id: "6c2276ce-fab3-4e03-94c7-7a6b2dcca263",
          artifact_sha256: "a".repeat(64),
          feature_set_version: "flow_v1@1",
          class_labels: ["BENIGN"],
          created_at: "2026-10-14T20:53:05Z",
          promoted_at: null,
          status_note: null,
          metrics_summary: {},
          promotion_gate: { eligible: false, problems: ["test macro-F1 is below the baseline"] },
          manifest: {},
        }),
      ),
      http.get(`${API}/models/${id}/drift-reports`, () =>
        HttpResponse.json([
          {
            report_id: "r1",
            period_start: "2026-01-06T00:00:00Z",
            period_end: "2026-01-11T00:00:00Z",
            status: "warning",
            metrics: { predicted_category_psi: 2.09 },
            warnings: ["predicted_category_psi = 2.091 >= 0.25"],
            created_at: "2026-10-15T00:00:00Z",
            note: "informational",
          },
        ]),
      ),
      http.post(`${API}/models/${id}/promote`, () =>
        problemResponse(problem(409, "Conflict", "promotion gate not met")),
      ),
    );
    renderApp(`/models/${id}`);
    expect(await screen.findByText("test macro-F1 is below the baseline")).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Promote" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Confirm" }));
    expect(await screen.findByText("promotion gate not met")).toBeInTheDocument();
    expect(screen.getByText("predicted_category_psi = 2.091 >= 0.25")).toBeInTheDocument();
    expect(
      screen.getByText(/They never retrain, re-threshold, or promote a model/),
    ).toBeInTheDocument();
  });

  it("treats a missing active classifier as an empty state", async () => {
    loggedInAs("viewer");
    server.use(
      http.get(`${API}/classification/summary`, () =>
        problemResponse(problem(404, "Not found", "no active model named 'attack_classifier'")),
      ),
      http.get(`${API}/classification/training-runs`, () => HttpResponse.json([])),
    );
    renderApp("/classification");
    expect(await screen.findByText("No active classifier")).toBeInTheDocument();
    expect(screen.getByText("No training runs yet")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("anomalies", () => {
  it("always shows the interpretation banner", async () => {
    loggedInAs("viewer");
    server.use(http.get(`${API}/anomalies`, () => HttpResponse.json(emptyPage)));
    renderApp("/anomalies");
    expect(
      await screen.findByText(
        "Unusual behaviour is not necessarily malicious. Anomaly scores are not probabilities.",
      ),
    ).toBeInTheDocument();
    expect(await screen.findByText("No anomaly results in this range")).toBeInTheDocument();
  });
});

describe("ingestion", () => {
  it("uploads as multipart form data with the CSRF token", async () => {
    loggedInAs("analyst");
    let csrf: string | null = null;
    let fields: Record<string, string> = {};
    server.use(
      http.get(`${API}/sources`, () =>
        HttpResponse.json([
          {
            source_id: 1,
            source_key: "synthetic",
            name: "Synthetic scenarios",
            source_type: "dataset",
            default_adapter: "canonical_jsonl",
            default_timezone: "UTC",
            reliability: "F",
            description: null,
            is_active: true,
          },
        ]),
      ),
      http.get(`${API}/adapters`, () => HttpResponse.json([])),
      http.get(`${API}/ingestion/batches`, () => HttpResponse.json(emptyPage)),
      http.post(`${API}/ingestion/uploads`, async ({ request }) => {
        csrf = request.headers.get("X-CSRF-Token");
        const form = await request.formData();
        fields = Object.fromEntries(
          [...form.entries()].map(([k, v]) => [k, typeof v === "string" ? v : v.name]),
        );
        return HttpResponse.json(
          { batch_id: "c8234486-c30d-4348-acc2-b3abd9d07cee", status: "queued", job_id: null },
          { status: 202 },
        );
      }),
    );
    renderApp("/ingestion");
    const user = userEvent.setup();
    await screen.findByRole("option", { name: "Synthetic scenarios (synthetic)" });
    await user.selectOptions(screen.getByLabelText("Source"), "1");
    const file = new File(['{"event_type":"auth"}\n'], "events.jsonl", {
      type: "application/json",
    });
    await user.upload(screen.getByLabelText("File"), file);
    await user.click(screen.getByRole("button", { name: "Upload" }));
    // jsdom does not preserve the multipart filename, so check the fields that were sent.
    await waitFor(() => expect(Object.keys(fields).sort()).toEqual(["file", "source_id"]));
    expect(fields.source_id).toBe("1");
    expect(csrf).toBe("csrf-analyst");
    expect(await screen.findByText("c8234486")).toBeInTheDocument();
  });
});

describe("web payload classifier card", () => {
  it("classifies parameter values and labels the scope", async () => {
    loggedInAs("analyst");
    let sent: unknown = null;
    server.use(
      http.get(`${API}/classification/summary`, () =>
        problemResponse(problem(404, "Not found", "no active model named 'attack_classifier'")),
      ),
      http.get(`${API}/classification/training-runs`, () => HttpResponse.json([])),
      http.post(`${API}/web-payloads/classify`, async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json({
          model: {
            name: "web_attack_classifier",
            version: 1,
            status: "active",
            algorithm: "logistic_regression",
          },
          note: "classifies individual HTTP parameter values only",
          results: [
            {
              index: 0,
              predicted_class: "BENIGN",
              is_attack_like: false,
              score: 0.98,
              score_kind: "x",
              empty_input: false,
              truncated: false,
            },
            {
              index: 1,
              predicted_class: "SQLI",
              is_attack_like: true,
              score: 0.99,
              score_kind: "x",
              empty_input: false,
              truncated: false,
            },
          ],
        });
      }),
    );
    renderApp("/classification");
    const user = userEvent.setup();
    const box = await screen.findByLabelText("Parameter values, one per line");
    await user.type(box, "calle mayor 5{enter}1' or 1=1 --");
    await user.click(screen.getByRole("button", { name: "Classify" }));
    const table = await screen.findByRole("table", { name: "Payload classifications" });
    expect(within(table).getByText("SQLI")).toBeInTheDocument();
    expect(within(table).getByText("1' or 1=1 --")).toBeInTheDocument();
    expect(sent).toEqual({ payloads: ["calle mayor 5", "1' or 1=1 --"] });
    expect(screen.getByText(/never blocks anything/)).toBeInTheDocument();
  });

  it("is hidden from viewers", async () => {
    loggedInAs("viewer");
    server.use(
      http.get(`${API}/classification/summary`, () =>
        problemResponse(problem(404, "Not found", "no active model")),
      ),
      http.get(`${API}/classification/training-runs`, () => HttpResponse.json([])),
    );
    renderApp("/classification");
    expect(await screen.findByText("No active classifier")).toBeInTheDocument();
    expect(screen.queryByLabelText("Parameter values, one per line")).not.toBeInTheDocument();
  });
});
