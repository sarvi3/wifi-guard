import { Link } from "@tanstack/react-router";
import { deviceStatus, useNetwork } from "@/lib/network-sim";
import { AnimatedNumber } from "@/components/AnimatedNumber";
import { cn } from "@/lib/utils";

/**
 * Who is actually eating the bandwidth, as a share-of-total bar chart.
 */
export function BandwidthShare({ focus }: { focus?: string | undefined }) {
  const { state } = useNetwork();
  const total = state.devices.reduce((a, d) => a + d.down, 0) || 1;
  const sorted = [...state.devices].sort((a, b) => b.down - a.down);
  const max = sorted[0]?.down || 1;

  return (
    <div className="panel p-5">
      <div className="flex items-center justify-between">
        <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
          who is using the bandwidth
        </p>
        <span className="font-mono text-[11px] text-muted-foreground">
          <AnimatedNumber value={total} decimals={1} suffix=" Mbps" />
        </span>
      </div>

      <ul className="mt-4 space-y-3">
        {sorted.map((d) => {
          const share = (d.down / total) * 100;
          const status = deviceStatus(d);
          return (
            <li key={d.id}>
              <div className="flex items-baseline gap-2">
                <span
                  className={cn(
                    "h-1.5 w-1.5 rounded-full",
                    status === "threatened"
                      ? "bg-danger wg-blip"
                      : status === "busy"
                        ? "bg-warn"
                        : "bg-safe",
                  )}
                />
                <Link
                  to="/health"
                  search={{ device: d.id }}
                  className={cn(
                    "truncate text-sm hover:text-primary",
                    focus === d.id ? "text-primary" : "text-foreground",
                  )}
                >
                  {d.name}
                </Link>
                <span className="ml-auto font-mono text-[11px] text-muted-foreground">
                  <AnimatedNumber value={share} suffix="%" /> ·{" "}
                  <AnimatedNumber value={d.down} decimals={1} suffix=" Mbps" />
                </span>
              </div>
              <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-muted">
                <div
                  className={cn(
                    "h-full rounded-full transition-[width] duration-700 ease-out",
                    status === "threatened"
                      ? "bg-danger"
                      : status === "busy"
                        ? "bg-warn"
                        : "bg-primary",
                  )}
                  style={{ width: `${Math.max(2, (d.down / max) * 100)}%` }}
                />
              </div>
            </li>
          );
        })}
      </ul>

      <p className="mt-4 text-xs leading-relaxed text-muted-foreground">
        Bars are scaled against the heaviest device, and percentages are the share of total download
        traffic right now.
      </p>
    </div>
  );
}
