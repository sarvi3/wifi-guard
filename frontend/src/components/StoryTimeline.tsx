import { PHASE_LABEL, PHASE_ORDER, useNetwork, type Phase } from "@/lib/network-sim";
import { cn } from "@/lib/utils";

const DESCRIPTION: Record<Phase, string> = {
  calm: "The network is operating normally.",
  recon: "The simulated rogue host is discovering devices on the subnet.",
  suspicious: "The rogue host is making a suspicious gateway claim.",
  intercept: "Traffic is being redirected through the simulated rogue host.",
  defense: "Host protection is rejecting the poisoned ARP entry.",
  recovered: "The poisoned route has been removed and normal traffic has resumed.",
};

export function StoryTimeline() {
  const { state } = useNetwork();

  const current = PHASE_ORDER.indexOf(state.phase);

  return (
    <section className="panel p-4">
      <div className="flex items-center justify-between">
        <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
          attack story
        </p>
      </div>

      <ol className="mt-4 space-y-0">
        {PHASE_ORDER.map((phase, i) => {
          const done = i < current;
          const active = i === current;

          const tone =
            phase === "intercept"
              ? "danger"
              : phase === "suspicious" || phase === "recon"
                ? "warn"
                : "safe";

          return (
            <li key={phase} className="flex gap-3">
              <div className="flex flex-col items-center">
                <span
                  className={cn(
                    "mt-1 h-2.5 w-2.5 shrink-0 rounded-full border transition-all duration-500",
                    active
                      ? tone === "danger"
                        ? "border-danger bg-danger wg-blip"
                        : tone === "warn"
                          ? "border-warn bg-warn wg-blip"
                          : "border-safe bg-safe"
                      : done
                        ? "border-primary/60 bg-primary/60"
                        : "border-border bg-muted",
                  )}
                />

                {i < PHASE_ORDER.length - 1 && (
                  <span
                    className={cn(
                      "my-0.5 w-px flex-1 transition-colors duration-500",
                      done ? "bg-primary/40" : "bg-border",
                    )}
                  />
                )}
              </div>

              <div className={cn("pb-4", !active && !done && "opacity-45")}>
                <p
                  className={cn(
                    "text-xs font-medium",
                    active && tone === "danger" && "text-danger",
                    active && tone === "warn" && "text-warn",
                    active && tone === "safe" && "text-safe",
                  )}
                >
                  {PHASE_LABEL[phase]}
                </p>

                <p className="mt-0.5 text-[11px] leading-relaxed text-muted-foreground">
                  {DESCRIPTION[phase]}
                </p>
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}