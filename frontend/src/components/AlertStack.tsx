import { Link } from "@tanstack/react-router";
import { HelpCircle, X } from "lucide-react";
import { useNetwork } from "@/lib/network-sim";

/**
 * Toast stack for hosts that cannot be matched to a known fingerprint.
 */
export function AlertStack() {
  const { state, resolveAlert } = useNetwork();
  if (!state.alerts.length) return null;

  return (
    <div className="pointer-events-none fixed bottom-5 right-5 z-40 flex w-80 flex-col gap-3">
      {state.alerts.map((a) => (
        <div
          key={a.id}
          className="panel pointer-events-auto border-warn/50 p-4 shadow-lg wg-slide-in"
          role="alert"
        >
          <div className="flex items-start gap-2">
            <HelpCircle className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
            <div className="min-w-0">
              <p className="text-sm font-medium text-warn">{a.title}</p>
              <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{a.detail}</p>
            </div>
            <button
              onClick={() => resolveAlert(a.id, "review")}
              className="ml-auto rounded p-0.5 text-muted-foreground hover:text-foreground"
              aria-label="Dismiss alert"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
            This host answered the scan but does not match any vendor fingerprint learned for your
            network.
          </p>
          <div className="mt-3 flex gap-2">
            <Link
              to="/defender"
              search={{ device: a.deviceId }}
              onClick={() => resolveAlert(a.id, "review")}
              className="flex-1 rounded-md bg-primary px-2.5 py-1.5 text-center text-xs font-medium text-primary-foreground transition-opacity hover:opacity-90"
            >
              Inspect
            </Link>
            <button
              onClick={() => resolveAlert(a.id, "block")}
              className="rounded-md border border-danger/50 px-2.5 py-1.5 text-xs text-danger transition-colors hover:bg-danger/15"
            >
              Block
            </button>
            <button
              onClick={() => resolveAlert(a.id, "ignore")}
              className="rounded-md border border-border px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-accent"
            >
              Trust
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
