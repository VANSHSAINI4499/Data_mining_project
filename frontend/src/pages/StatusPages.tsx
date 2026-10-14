import { Link } from "react-router";

import type { Role } from "../api/types";

export function NotFoundPage() {
  return (
    <section>
      <h1 className="text-xl font-semibold">Page not found</h1>
      <p className="mt-2 text-sm text-muted">
        This address does not exist.{" "}
        <Link to="/" className="text-accent underline">
          Go to the overview
        </Link>
        .
      </p>
    </section>
  );
}

export function ForbiddenPage({ role }: { role: Role }) {
  return (
    <section>
      <h1 className="text-xl font-semibold">Access denied</h1>
      <p className="mt-2 text-sm text-muted">You need the {role} role to view this page.</p>
    </section>
  );
}
