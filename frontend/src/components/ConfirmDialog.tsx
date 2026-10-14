import { useState, type ReactNode } from "react";

import { Button } from "./ui";

/** In-app confirmation for irreversible actions (never window.confirm). */
export function ConfirmButton({
  label,
  title,
  description,
  onConfirm,
  disabled,
  variant = "default",
  children,
  confirmDisabled,
}: {
  label: string;
  title: string;
  description: ReactNode;
  onConfirm: () => void;
  disabled?: boolean;
  variant?: "default" | "primary" | "danger";
  /** Extra inputs (e.g., a reason) rendered inside the dialog. */
  children?: ReactNode;
  confirmDisabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant={variant} disabled={disabled} onClick={() => setOpen(true)}>
        {label}
      </Button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-title"
            className="w-full max-w-md space-y-3 rounded border border-line bg-surface p-4 shadow"
          >
            <h2 id="confirm-title" className="font-medium">
              {title}
            </h2>
            <div className="text-sm">{description}</div>
            {children}
            <div className="flex justify-end gap-2">
              <Button onClick={() => setOpen(false)}>Cancel</Button>
              <Button
                variant={variant === "default" ? "primary" : variant}
                disabled={confirmDisabled}
                onClick={() => {
                  onConfirm();
                  setOpen(false);
                }}
              >
                Confirm
              </Button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
