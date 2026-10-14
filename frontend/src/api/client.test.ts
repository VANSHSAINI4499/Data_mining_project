import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import { API, problem, problemResponse, server } from "../test/server";
import { ApiError, apiRequest, onUnauthorized, setCsrfToken } from "./client";

describe("apiRequest", () => {
  it("sends the CSRF token on state-changing requests only", async () => {
    const seen: Record<string, string | null> = {};
    server.use(
      http.get(`${API}/echo`, ({ request }) => {
        seen.GET = request.headers.get("X-CSRF-Token");
        return HttpResponse.json({});
      }),
      http.post(`${API}/echo`, ({ request }) => {
        seen.POST = request.headers.get("X-CSRF-Token");
        return HttpResponse.json({});
      }),
    );
    setCsrfToken("tok-123");
    await apiRequest("/echo");
    await apiRequest("/echo", { method: "POST", body: {} });
    expect(seen).toEqual({ GET: null, POST: "tok-123" });
  });

  it("turns problem+json responses into ApiError with request id", async () => {
    server.use(
      http.get(`${API}/broken`, () =>
        problemResponse(problem(409, "Conflict", "job is already succeeded")),
      ),
    );
    const error = await apiRequest("/broken").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.status).toBe(409);
    expect(apiError.message).toBe("job is already succeeded");
    expect(apiError.requestId).toBe("req-test-1");
  });

  it("reports network failures without inventing data", async () => {
    server.use(http.get(`${API}/down`, () => HttpResponse.error()));
    const error = (await apiRequest("/down").catch((e: unknown) => e)) as ApiError;
    expect(error.status).toBe(0);
    expect(error.message).toMatch(/cannot reach/i);
  });

  it("returns undefined for 204 responses", async () => {
    server.use(http.post(`${API}/empty`, () => new HttpResponse(null, { status: 204 })));
    await expect(apiRequest("/empty", { method: "POST" })).resolves.toBeUndefined();
  });

  it("notifies unauthorized listeners on 401", async () => {
    const listener = vi.fn();
    const unsubscribe = onUnauthorized(listener);
    server.use(
      http.get(`${API}/private`, () =>
        problemResponse(problem(401, "Authentication required", "expired")),
      ),
    );
    await apiRequest("/private").catch(() => undefined);
    unsubscribe();
    expect(listener).toHaveBeenCalledOnce();
  });
});
