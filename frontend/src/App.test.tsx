import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { PLANNED_PAGES } from "./lib/navigation";
import { renderApp } from "./test/render";
import { API, problem, problemResponse, server, sessionFor } from "./test/server";

function loggedInAs(role: "viewer" | "analyst" | "admin") {
  server.use(http.get(`${API}/auth/me`, () => HttpResponse.json(sessionFor(role))));
}

describe("authentication", () => {
  it("shows the login page when there is no session", async () => {
    renderApp("/events");
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeInTheDocument();
  });

  it("logs in and returns to the originally requested page", async () => {
    server.use(
      http.post(`${API}/auth/login`, async ({ request }) => {
        const body = (await request.json()) as { username: string; password: string };
        return body.password === "right-passphrase"
          ? HttpResponse.json(sessionFor("analyst", body.username))
          : problemResponse(
              problem(401, "Authentication required", "Invalid username or password"),
            );
      }),
    );
    renderApp("/events");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/password/i), "right-passphrase");
    await user.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Event explorer" })).toBeInTheDocument();
  });

  it("shows a generic message on failed login", async () => {
    server.use(
      http.post(`${API}/auth/login`, () =>
        problemResponse(problem(401, "Authentication required", "Invalid username or password")),
      ),
    );
    renderApp("/");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/password/i), "wrong");
    await user.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password.");
  });

  it("signs out with the CSRF token and returns to login", async () => {
    loggedInAs("viewer");
    let csrf: string | null = null;
    server.use(
      http.post(`${API}/auth/logout`, ({ request }) => {
        csrf = request.headers.get("X-CSRF-Token");
        return new HttpResponse(null, { status: 204 });
      }),
    );
    renderApp("/");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /sign out/i }));
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeInTheDocument();
    expect(csrf).toBe("csrf-viewer");
  });

  it("shows an error, not the login page, when the backend is unreachable", async () => {
    server.use(http.get(`${API}/auth/me`, () => HttpResponse.error()));
    renderApp("/");
    expect(await screen.findByRole("alert")).toHaveTextContent(/cannot reach the backend/i);
  });
});

describe("overview system status", () => {
  it("lists readiness checks from the API", async () => {
    loggedInAs("viewer");
    renderApp("/");
    expect(await screen.findByText("Backend is ready.")).toBeInTheDocument();
    expect(screen.getByText("Database migrations")).toBeInTheDocument();
    expect(await screen.findByText("API version 0.1.0")).toBeInTheDocument();
  });

  it("shows failing checks when the backend is not ready", async () => {
    loggedInAs("viewer");
    server.use(
      http.get(`${API}/health/ready`, () =>
        problemResponse(
          problem(503, "Service not ready", "failing checks: migrations", {
            checks: {
              database: { status: "ok" },
              migrations: { status: "fail", detail: "migrations_behind" },
            },
          }),
        ),
      ),
    );
    renderApp("/");
    expect(await screen.findByText("Backend is not ready.")).toBeInTheDocument();
    expect(screen.getByText("Failing: migrations_behind")).toBeInTheDocument();
  });

  it("shows an honest empty state and checklist when there is no data", async () => {
    loggedInAs("admin");
    renderApp("/");
    expect(await screen.findByText("No security analytics yet")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Getting started" })).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByRole("figure")).not.toBeInTheDocument();
  });
});

describe("navigation and planned pages", () => {
  it("hides admin-only pages from viewers and shows them to admins", async () => {
    loggedInAs("viewer");
    const { unmount } = renderApp("/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).queryByRole("link", { name: "Audit history" })).not.toBeInTheDocument();
    unmount();

    loggedInAs("admin");
    renderApp("/");
    const adminNav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(adminNav).getByRole("link", { name: "Audit history" })).toBeInTheDocument();
  });

  it("denies admin pages to viewers who navigate directly", async () => {
    loggedInAs("viewer");
    renderApp("/audit");
    expect(await screen.findByRole("heading", { name: "Access denied" })).toBeInTheDocument();
  });

  it.each(PLANNED_PAGES.map((p) => [p.label, p.path] as const))(
    "%s shows a not-yet-available state with no data",
    async (label, path) => {
      loggedInAs("admin");
      renderApp(path);
      const page = await screen.findByTestId("planned-feature");
      expect(within(page).getByRole("heading", { name: label })).toBeInTheDocument();
      expect(page).toHaveTextContent("This page is not available yet.");
      expect(within(page).queryByRole("table")).not.toBeInTheDocument();
      expect(within(page).queryByRole("figure")).not.toBeInTheDocument();
    },
  );

  it("renders implemented pages instead of placeholders", async () => {
    loggedInAs("viewer");
    renderApp("/events");
    expect(await screen.findByRole("heading", { name: "Event explorer" })).toBeInTheDocument();
    expect(screen.queryByTestId("planned-feature")).not.toBeInTheDocument();
    expect(
      await screen.findByText("No events match these filters in the selected range"),
    ).toBeInTheDocument();
  });

  it("shows a not-found page for unknown routes", async () => {
    loggedInAs("viewer");
    renderApp("/no/such/page");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });

  it("returns to login when an API call reports the session expired", async () => {
    let calls = 0;
    server.use(
      http.get(`${API}/auth/me`, () => {
        calls += 1;
        return HttpResponse.json(sessionFor("viewer"));
      }),
      http.get(`${API}/health/ready`, () =>
        problemResponse(problem(401, "Authentication required", "Session expired")),
      ),
    );
    renderApp("/");
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: /sign in/i })).toBeInTheDocument(),
    );
    expect(calls).toBe(1);
  });
});
