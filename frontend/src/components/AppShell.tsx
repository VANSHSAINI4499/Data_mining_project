import { Suspense, useSyncExternalStore } from "react";
import { NavLink, Outlet } from "react-router";

import type { User } from "../api/types";
import { hasRole, useLogout } from "../hooks/useSession";
import { getTimeDisplay, setTimeDisplay, subscribeTimeDisplay } from "../lib/format";
import { getLiveMode, setLiveMode, subscribeLiveMode } from "../lib/liveMode";
import { NAV_PAGES } from "../lib/navigation";
import { LoadingSkeleton } from "./States";

const linkClass = ({ isActive }: { isActive: boolean }) =>
  `block rounded px-3 py-1.5 text-sm ${
    isActive ? "bg-accent text-white" : "text-ink hover:bg-canvas"
  }`;

export function AppShell({ user }: { user: User }) {
  const logout = useLogout();
  const items = NAV_PAGES.filter((item) => hasRole(user, item.minRole));
  const timeDisplay = useSyncExternalStore(subscribeTimeDisplay, getTimeDisplay);
  const live = useSyncExternalStore(subscribeLiveMode, getLiveMode);

  return (
    <div className="flex h-full">
      <aside className="w-56 shrink-0 border-r border-line bg-surface p-3">
        <p className="mb-4 px-3 text-lg font-semibold">CTI Warehouse</p>
        <nav aria-label="Main">
          <ul className="space-y-1">
            <li>
              <NavLink to="/" end className={linkClass}>
                Overview
              </NavLink>
            </li>
            {items.map((item) => (
              <li key={item.path}>
                <NavLink to={item.path} className={linkClass}>
                  {item.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-end gap-4 border-b border-line bg-surface px-6 py-3 text-sm">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={live} onChange={(e) => setLiveMode(e.target.checked)} />
            <span className="text-muted">Live</span>
          </label>
          <label className="flex items-center gap-2">
            <span className="text-muted">Times shown in</span>
            <select
              aria-label="Time display"
              className="rounded border border-line bg-surface px-2 py-1"
              value={timeDisplay}
              onChange={(e) => setTimeDisplay(e.target.value === "local" ? "local" : "utc")}
            >
              <option value="utc">UTC</option>
              <option value="local">Local time</option>
            </select>
          </label>
          <span>
            Signed in as <strong>{user.username}</strong>{" "}
            <span className="text-muted">({user.role})</span>
          </span>
          <button
            type="button"
            onClick={() => logout.mutate()}
            disabled={logout.isPending}
            className="rounded border border-line px-3 py-1 hover:bg-canvas disabled:opacity-50"
          >
            Sign out
          </button>
        </header>
        {/* Keyed so every formatted time re-renders when the display preference changes. */}
        <main key={timeDisplay} className="flex-1 overflow-auto p-6">
          <Suspense fallback={<LoadingSkeleton label="Loading page" />}>
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  );
}
