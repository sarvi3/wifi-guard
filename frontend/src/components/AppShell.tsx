import { Link, useRouterState } from "@tanstack/react-router";
import { Beaker, Activity, Bot, Radar, ShieldAlert, Wifi, Pause, Play } from "lucide-react";
import type { ReactNode } from "react";
import { useNetwork } from "@/lib/network-sim";
import { ThreatConfidence } from "@/components/ThreatConfidence";
import { AlertStack } from "@/components/AlertStack";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Dashboard", icon: Radar, exact: true },
  { to: "/health", label: "WiFi Health", icon: Activity, exact: false },
  { to: "/defender", label: "Threat Defender", icon: ShieldAlert, exact: false },
  { to: "/attack-lab", label: "Attack Lab", icon: Beaker, exact: false },
  { to: "/assistant", label: "AI Assistant", icon: Bot, exact: false },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const { state, togglePause } = useNetwork();
  const pathname = useRouterState({ select: (r) => r.location.pathname });

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="fixed inset-y-0 left-0 z-20 flex w-56 flex-col border-r border-sidebar-border bg-sidebar">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <span className="relative flex h-8 w-8 items-center justify-center rounded-md bg-primary/15 text-primary">
            <Wifi className="h-4 w-4" />
          </span>
          <div className="leading-tight">
            <p className="text-sm font-semibold tracking-tight">WiFi Guard</p>
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
              network os
            </p>
          </div>
        </div>

        <nav className="flex flex-1 flex-col gap-1 px-3">
          {NAV.map((item) => {
            const active = item.exact ? pathname === item.to : pathname.startsWith(item.to);
            return (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-sidebar-accent text-sidebar-accent-foreground"
                    : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground",
                )}
              >
                <item.icon className={cn("h-4 w-4", active && "text-primary")} />
                {item.label}
                {item.to === "/defender" && state.status !== "SAFE" && (
                  <span className="ml-auto h-1.5 w-1.5 rounded-full bg-danger wg-blip" />
                )}
              </Link>
            );
          })}
        </nav>

        <div className="border-t border-sidebar-border p-4">
          <ThreatConfidence variant="compact" />
        </div>
      </aside>

      <div className="ml-56 flex min-h-screen flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-14 items-center gap-4 border-b border-border bg-background/85 px-6 backdrop-blur">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "h-2 w-2 rounded-full",
                state.status === "SAFE"
                  ? "bg-safe"
                  : state.status === "WARNING"
                    ? "bg-warn"
                    : "bg-danger wg-blip",
              )}
            />
            <span className="font-mono text-xs tracking-wide text-foreground">GUARDNET-5G</span>
          </div>
          <span className="font-mono text-[11px] text-muted-foreground">
            {state.devices.filter((d) => d.online).length} devices ·{" "}
            {state.packets.length} packets in flight
          </span>
          <div className="ml-auto flex items-center gap-4">
            <span className="font-mono text-[11px] text-muted-foreground">
              {state.scanning ? "scanning…" : `last scan ${timeAgo(state.lastScan)}`}
            </span>
            <button
              onClick={togglePause}
              className="flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1 font-mono text-[11px] text-muted-foreground transition-colors hover:text-foreground"
            >
              {state.paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
              {state.paused ? "resume" : "live"}
            </button>
          </div>
        </header>

        <main key={pathname} className="wg-page-in flex-1">
          {children}
        </main>
      </div>
      <AlertStack />
    </div>
  );
}

export function timeAgo(ts: number) {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}
