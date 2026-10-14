import { NavLink, Outlet } from "react-router";

import type { User } from "../api/types";
import { hasRole, useLogout } from "../hooks/useSession";
import { NAV_PAGES } from "../lib/navigation";

const linkClass = ({ isActive }: { isActive: boolean }) =>
  `block rounded px-3 py-1.5 text-sm ${
    isActive ? "bg-accent text-white" : "text-ink hover:bg-canvas"
  }`;

export function AppShell({ user }: { user: User }) {
  const logout = useLogout();
  const items = NAV_PAGES.filter((item) => hasRole(user, item.minRole));

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
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
