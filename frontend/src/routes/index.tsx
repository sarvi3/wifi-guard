import { createFileRoute, Link } from "@tanstack/react-router";
import { Activity, ArrowRight, RefreshCw, ShieldAlert, ShieldCheck, Wifi } from "lucide-react";
import { useNetwork } from "@/lib/network-sim";
import { ThreatConfidence } from "@/components/ThreatConfidence";
import { MiniMap } from "@/components/MiniMap";
import { AnimatedNumber } from "@/components/AnimatedNumber";
import { timeAgo } from "@/components/AppShell";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "WiFi Guard — Network Overview" },
      {
        name: "description",
        content:
          "A live overview of your WiFi network: health verdict, connected devices, active threats and recent activity.",
      },
      { property: "og:title", content: "WiFi Guard — Network Overview" },
      {
        property: "og:description",
        content: "A live overview of your WiFi network: health verdict, connected devices, active threats and recent activity.",
      },
    ],
  }),
  component: Dashboard,
});

function Dashboard() {
  const { state, runScan } = useNetwork();
  const threats = state.events
    .filter((e) => e.severity === "danger" || e.severity === "warn")
    .slice(-6)
    .reverse();
  const verdict =
    state.status === "SAFE" ? "Healthy" : state.status === "WARNING" ? "Degraded" : "Under attack";
  const totalDown = state.devices.reduce((a, d) => a + d.down, 0);

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-muted-foreground">
            overview
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">Your network right now</h1>
        </div>
        <button
          onClick={runScan}
          disabled={state.scanning}
          className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm text-foreground transition-colors hover:bg-accent disabled:opacity-60"
        >
          <RefreshCw className={cn("h-4 w-4", state.scanning && "animate-spin")} />
          {state.scanning ? "Scanning" : "Run scan"}
        </button>
      </header>

      {!state.hasScanned && (
        <div className="panel mt-6 p-6">
          <div className="flex flex-col items-center text-center">
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
              ready to scan
            </p>

            <h2 className="mt-2 text-xl font-semibold tracking-tight">
              Scan your Wi-Fi network
            </h2>

            <p className="mt-2 max-w-xl text-sm text-muted-foreground">
              Run a scan to discover the devices connected to your Wi-Fi
              and see your real network security status.
            </p>

            <button
              onClick={runScan}
              disabled={state.scanning}
              className="mt-5 flex items-center gap-2 rounded-md bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-60"
            >
              <RefreshCw
                className={cn("h-4 w-4", state.scanning && "animate-spin")}
              />
              {state.scanning ? "Scanning..." : "Run Network Scan"}
            </button>
          </div>
        </div>
      )}

      <div className="mt-6 grid gap-4 md:grid-cols-3">
        <div className="panel p-5 md:col-span-2">
          <div className="flex items-start justify-between">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
                network verdict
              </p>
              <p
                className={cn(
                  "mt-2 text-3xl font-semibold tracking-tight",
                  state.status === "SAFE"
                    ? "text-safe"
                    : state.status === "WARNING"
                      ? "text-warn"
                      : "text-danger",
                )}
              >
                {verdict}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                Last scan {timeAgo(state.lastScan)} · <AnimatedNumber value={totalDown} suffix=" Mbps" /> flowing through the
                gateway
              </p>
            </div>
            {state.status === "SAFE" ? (
              <ShieldCheck className="h-8 w-8 text-safe" />
            ) : (
              <ShieldAlert className="h-8 w-8 text-danger" />
            )}
          </div>
          <div className="mt-6">
            <ThreatConfidence variant="hero" />
          </div>
        </div>

        <div className="panel p-5">
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
            connected devices
          </p>
          <p className="mt-2 text-3xl font-semibold"><AnimatedNumber value={state.devices.filter((d) => d.online).length} /></p>
          <ul className="mt-4 space-y-2">
            {state.devices.map((d) => (
              <li key={d.id} className="flex items-center gap-2 text-sm">
                <span
                  className={cn(
                    "h-1.5 w-1.5 rounded-full",
                    !d.online
                      ? "bg-muted"
                      : d.hostile || d.threats > 0
                        ? "bg-danger wg-blip"
                        : d.down > 20
                          ? "bg-warn"
                          : "bg-safe",
                  )}
                />
                <Link
                  to="/defender"
                  search={{ device: d.id }}
                  className="truncate text-foreground hover:text-primary"
                >
                  {d.name}
                </Link>
                <span className="ml-auto font-mono text-[11px] text-muted-foreground">
                  <AnimatedNumber value={d.down} decimals={1} />
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <Link
        to="/defender" search={{ device: undefined }}
        className="panel mt-4 flex flex-col gap-4 p-5 transition-colors hover:bg-accent/20 sm:flex-row sm:items-center"
      >
        <div className="h-40 w-full shrink-0 sm:w-80">
          <MiniMap />
        </div>
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
            live network preview
          </p>
          <p className="mt-2 text-sm text-foreground">
            {state.devices.filter((d) => d.online).length} hosts around the gateway, with{" "}
            {state.packets.length} packets in flight right now.
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Open Threat Defender for the full map, packet inspector and attack lab.
          </p>
        </div>
        <ArrowRight className="ml-auto hidden h-4 w-4 text-muted-foreground sm:block" />
      </Link>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div className="panel p-5">
          <div className="flex items-center justify-between">
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
              active threats
            </p>
            <Link to="/defender" search={{device:undefined}} className="text-xs text-primary hover:underline">
              Open Threat Defender
            </Link>
          </div>
          {threats.length === 0 ? (
            <p className="mt-4 text-sm text-muted-foreground">
              Nothing hostile on the network. Every device is answering with its known hardware
              address.
            </p>
          ) : (
            <ul className="mt-3 divide-y divide-border">
              {threats.map((e) => (
                <li key={e.id}>
                  <Link
                    to="/defender"
                    search={{ device: e.deviceId }}
                    className="group flex items-center gap-3 py-3 transition-colors hover:text-primary"
                  >
                    <ShieldAlert
                      className={cn(
                        "h-4 w-4",
                        e.severity === "danger" ? "text-danger" : "text-warn"
                      )}
                    />

                    <span className="text-sm">{e.label}</span>

                    <span className="ml-auto font-mono text-[11px] text-muted-foreground">
                      {e.time}
                    </span>

                    <ArrowRight className="h-3.5 w-3.5 opacity-0 transition-opacity group-hover:opacity-100" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="panel p-5">
          <div className="flex items-center justify-between">
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
              recent activity
            </p>
            <Link to="/assistant" search={{ device: undefined, event: undefined }} className="text-xs text-primary hover:underline">
              Explain with AI
            </Link>
          </div>
          <ul className="mt-3 space-y-3">
            {[...state.events]
              .reverse()
              .slice(0, 6)
              .map((e) => (
                <li key={e.id} className="flex gap-3 text-sm">
                  <span className="font-mono text-[11px] text-muted-foreground">{e.time}</span>
                  <span
                    className={cn(
                      "flex-1",
                      e.severity === "danger"
                        ? "text-danger"
                        : e.severity === "warn"
                          ? "text-warn"
                          : e.severity === "good"
                            ? "text-safe"
                            : "text-foreground",
                    )}
                  >
                    {e.label}
                  </span>
                </li>
              ))}
          </ul>
        </div>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Link to="/health" search={{device:undefined}} className="panel flex items-center gap-3 p-5 transition-colors hover:bg-accent/40">
          <Activity className="h-5 w-5 text-primary" />
          <div>
            <p className="text-sm font-medium">WiFi Health Monitor</p>
            <p className="text-xs text-muted-foreground">
              Why the network feels slow, and which device is responsible
            </p>
          </div>
          <ArrowRight className="ml-auto h-4 w-4 text-muted-foreground" />
        </Link>
        <Link
          to="/defender"
          search={{device:undefined}}
          className="panel flex items-center gap-3 p-5 transition-colors hover:bg-accent/40"
        >
          <Wifi className="h-5 w-5 text-primary" />
          <div>
            <p className="text-sm font-medium">Threat Defender</p>
            <p className="text-xs text-muted-foreground">
              Watch packets move between your devices in real time
            </p>
          </div>
          <ArrowRight className="ml-auto h-4 w-4 text-muted-foreground" />
        </Link>
      </div>
    </div>
  );
}
