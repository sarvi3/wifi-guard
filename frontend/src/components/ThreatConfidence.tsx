import { ArrowDownRight, ArrowUpRight, Minus, ShieldAlert, ShieldCheck } from "lucide-react";
import { AnimatedNumber } from "@/components/AnimatedNumber";
import { useNetwork } from "@/lib/network-sim";
import { cn } from "@/lib/utils";

const TOTAL = 16;

const TREND_COPY = {
  falling: "Decreasing — evidence of an attack is building",
  recovering: "Recovering — defenses are holding",
  stable: "Stable — matching the learned baseline",
} as const;

/**
 * The hero metric of the whole product. Every page shows this so the
 * number the user learns to read is always the same one.
 */
export function ThreatConfidence({
  variant = "panel",
  threatScore,
  severity,
}: {
  variant?: "hero" | "panel" | "compact";
  threatScore?: number;
  severity?: string;
}) {
  const { state } = useNetwork();
  
  // Use real API data if provided, otherwise fall back to simulated state
  const score = threatScore !== undefined ? threatScore : state.threat;
  const status = severity || state.status;
  
  const filled = Math.round((score / 100) * TOTAL);
  const tone =
    status === "SAFE" ? "bg-safe" : status === "WARNING" ? "bg-warn" : status === "HIGH RISK" ? "bg-danger" : "bg-danger";
  const text =
    status === "SAFE" ? "text-safe" : status === "WARNING" ? "text-warn" : status === "HIGH RISK" ? "text-danger" : "text-danger";
  const TrendIcon =
    state.trend === "falling" ? ArrowDownRight : state.trend === "recovering" ? ArrowUpRight : Minus;

  if (variant === "compact") {
    return (
      <div className="w-full">
        <div className="flex items-baseline justify-between">
          <span className={cn("font-mono text-[10px] uppercase tracking-[0.2em]", text)}>
            {status}
          </span>
          <span className="font-mono text-xs text-foreground">
            <AnimatedNumber value={score} suffix="%" />
          </span>
        </div>
        <Segments filled={filled} tone={tone} status={status} className="mt-2 h-2" />
        <p className="mt-2 flex items-center gap-1 font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">
          <TrendIcon className={cn("h-3 w-3", state.trend !== "stable" && text)} />
          threat confidence
        </p>
      </div>
    );
  }

  const hero = variant === "hero";

  return (
    <div className="w-full">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-muted-foreground">
            threat confidence
          </p>
          <div className="mt-1 flex items-end gap-2">
            <AnimatedNumber
              value={score}
              className={cn(
                "font-semibold tabular-nums tracking-tight",
                hero ? "text-6xl" : "text-4xl",
                text,
              )}
            />
            <span className={cn("pb-1 font-mono", hero ? "text-xl" : "text-base", text)}>%</span>
            <span
              className={cn(
                "mb-1.5 ml-2 rounded-full px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider",
                status === "SAFE"
                  ? "bg-safe/15 text-safe"
                  : status === "WARNING"
                    ? "bg-warn/15 text-warn"
                    : status === "HIGH RISK"
                      ? "bg-danger/15 text-danger"
                      : "bg-danger/15 text-danger",
              )}
            >
              {status}
            </span>
          </div>
        </div>
        {status === "SAFE" ? (
          <ShieldCheck className={cn("text-safe", hero ? "h-9 w-9" : "h-6 w-6")} />
        ) : (
          <ShieldAlert
            className={cn("text-danger wg-blip", hero ? "h-9 w-9" : "h-6 w-6")}
          />
        )}
      </div>

      <Segments
        filled={filled}
        tone={tone}
        status={status}
        className={cn("mt-4", hero ? "h-4" : "h-3")}
      />

      <p className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground">
        <TrendIcon className={cn("h-3.5 w-3.5", state.trend !== "stable" ? text : "")} />
        {TREND_COPY[state.trend]}
      </p>
    </div>
  );
}

function Segments({
  filled,
  tone,
  status,
  className,
}: {
  filled: number;
  tone: string;
  status: string;
  className?: string;
}) {
  return (
    <div className={cn("flex gap-[3px]", className)}>
      {Array.from({ length: TOTAL }).map((_, i) => (
        <span
          key={i}
          className={cn(
            "flex-1 rounded-[2px] transition-colors duration-500",
            i < filled ? tone : "bg-muted",
            i === filled - 1 && status !== "SAFE" && "wg-blip",
          )}
        />
      ))}
    </div>
  );
}

/** Backwards-compatible alias used by older call sites. */
export function ThreatMeter({ compact = false }: { compact?: boolean }) {
  return <ThreatConfidence variant={compact ? "compact" : "panel"} />;
}
