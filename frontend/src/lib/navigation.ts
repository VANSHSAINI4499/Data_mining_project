import type { Role } from "../api/types";

export interface NavItem {
  path: string;
  label: string;
  minRole: Role;
  /** Roadmap milestone that delivers the page (IMPLEMENTATION_ROADMAP.md). */
  milestone: string;
  /** What the page will show, used in its "not yet available" state. */
  summary: string;
  /** Detail routes rendered by the same planned page. */
  detailPaths?: string[];
}

// Routes from FRONTEND_SPECIFICATION.md §3. The overview is implemented separately.
export const PLANNED_PAGES: NavItem[] = [
  {
    path: "/ingestion",
    label: "Data ingestion",
    minRole: "viewer",
    milestone: "6.2",
    summary: "Upload files, track ingestion batches, and review rejected records.",
    detailPaths: ["/ingestion/batches/:batchId"],
  },
  {
    path: "/events",
    label: "Event explorer",
    minRole: "viewer",
    milestone: "6.2",
    summary: "Filter and inspect normalised security events with full provenance.",
    detailPaths: ["/events/:eventId"],
  },
  {
    path: "/classification",
    label: "Classification",
    minRole: "viewer",
    milestone: "6.3",
    summary: "Training runs, per-class metrics, confusion matrices, and predictions.",
    detailPaths: ["/classification/runs/:runId"],
  },
  {
    path: "/anomalies",
    label: "Anomalies",
    minRole: "viewer",
    milestone: "6.3",
    summary: "Unusual host, account, and network behaviour compared with baselines.",
    detailPaths: ["/anomalies/:resultId"],
  },
  {
    path: "/threat-intel",
    label: "Threat intelligence",
    minRole: "viewer",
    milestone: "6.4",
    summary: "Feeds, indicators, matches, and MITRE ATT&CK references.",
    detailPaths: ["/threat-intel/indicators/:indicatorId"],
  },
  {
    path: "/alerts",
    label: "Alerts",
    minRole: "viewer",
    milestone: "6.4",
    summary: "Correlated alerts (hypotheses for review) with risk breakdowns and evidence.",
    detailPaths: ["/alerts/:alertId"],
  },
  {
    path: "/cases",
    label: "Cases",
    minRole: "viewer",
    milestone: "6.4",
    summary: "Investigations with timelines, notes, and dispositions.",
    detailPaths: ["/cases/:caseId"],
  },
  {
    path: "/models",
    label: "Model registry",
    minRole: "viewer",
    milestone: "6.3",
    summary: "Model versions, manifests, evaluation reports, and promotions.",
    detailPaths: ["/models/:modelId"],
  },
  {
    path: "/data-quality",
    label: "Data quality",
    minRole: "viewer",
    milestone: "6.2",
    summary: "Data-quality check results per source and ingestion batch.",
  },
  {
    path: "/settings",
    label: "Settings",
    minRole: "viewer",
    milestone: "6.5",
    summary: "Users, sources, feeds, correlation rules, and assets.",
  },
  {
    path: "/audit",
    label: "Audit history",
    minRole: "admin",
    milestone: "6.5",
    summary: "Read-only record of who changed what, and when.",
  },
];
