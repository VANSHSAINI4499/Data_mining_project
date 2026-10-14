import { type FormEvent, useState } from "react";

import { useLogin } from "../hooks/useSession";

export function LoginPage() {
  const login = useLogin();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const submit = (event: FormEvent) => {
    event.preventDefault();
    login.mutate({ username, password });
  };

  const error = login.error;
  const message =
    error === null
      ? null
      : error.status === 401
        ? "Invalid username or password."
        : error.status === 429
          ? "Too many attempts. Please wait before trying again."
          : error.message;

  return (
    <div className="flex h-full items-center justify-center">
      <form
        onSubmit={submit}
        aria-labelledby="login-title"
        className="w-80 space-y-4 rounded border border-line bg-surface p-6 shadow-sm"
      >
        <h1 id="login-title" className="text-lg font-semibold">
          Sign in to CTI Warehouse
        </h1>
        <label className="block text-sm">
          Username
          <input
            name="username"
            autoComplete="username"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="mt-1 block w-full rounded border border-line px-2 py-1"
          />
        </label>
        <label className="block text-sm">
          Password
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 block w-full rounded border border-line px-2 py-1"
          />
        </label>
        {message && (
          <p role="alert" className="text-sm text-danger">
            {message}
          </p>
        )}
        <button
          type="submit"
          disabled={login.isPending}
          className="w-full rounded bg-accent px-3 py-1.5 text-white disabled:opacity-50"
        >
          {login.isPending ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
