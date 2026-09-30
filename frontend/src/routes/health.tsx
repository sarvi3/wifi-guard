import { createFileRoute, Link } from "@tanstack/react-router";
import { Gauge, Signal, TrendingDown, Waves, AlertCircle, RefreshCw } from "lucide-react";
import { useNetwork } from "@/lib/network-sim";
import { cn } from "@/lib/utils";
import { useState, useEffect, useRef } from "react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export const Route = createFileRoute("/health")({
  validateSearch: (s: Record<string, unknown>) => ({
    device: typeof s["device"] === "string" ? s["device"] : undefined,
  }),
  head: () => ({
    meta: [
      { title: "WiFi Health Monitor — WiFi Guard" },
      {
        name: "description",
        content:
          "Bandwidth, latency, packet loss and signal quality per device, with plain-language tips to make your WiFi faster.",
      },
      { property: "og:title", content: "WiFi Health Monitor — WiFi Guard" },
      {
        property: "og:description",
        content: "See exactly which device is slowing your WiFi down and what to do about it.",
      },
    ],
  }),
  component: HealthPage,
});

function HealthPage() {
  const { device: focus } = Route.useSearch();
  const { state } = useNetwork();
  const [healthData, setHealthData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [trafficHistory, setTrafficHistory] = useState<Array<{ time: string, download: number, upload: number }>>([]);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const isFirstLoadRef = useRef(true);

  useEffect(() => {
    async function fetchHealthData(isInitial: boolean = false) {
      try {
        if (isInitial) {
          setLoading(true);
        }
        setError(null);
        const response = await fetch('https://wifi-guard-production.up.railway.app/network-health');
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        setHealthData(data);

        // Add traffic measurement to history
        if (data.throughput && data.throughput.success) {
          const newEntry = {
            time: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            download: data.throughput.current_traffic_download_mbps || 0,
            upload: data.throughput.current_traffic_upload_mbps || 0
          };
          setTrafficHistory(prev => [...prev.slice(-29), newEntry]);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch health data');
      } finally {
        if (isInitial) {
          setLoading(false);
          isFirstLoadRef.current = false;
        }
      }
    }

    // Initial fetch
    fetchHealthData(false);

    // Set up polling every 5 seconds (background updates, no loading state)
    pollingIntervalRef.current = setInterval(() => {
      fetchHealthData(false);
    }, 49500);

    // Clean up on unmount
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
    };
  }, []);

  // Use shared network state for devices
  const sharedDevices = state.devices;

  // Use real API data for health metrics
  const overallHealth = healthData?.overall_health;

  const healthScore =
    state.status === "SAFE" ? 92 :
    state.status === "WARNING" ? 60 :
    30;

  const healthStatus =
    state.status === "SAFE" ? "Healthy" :
    state.status === "WARNING" ? "Degraded" :
    "Under attack";

  const throughput = healthData?.throughput;
  const jitter = healthData?.jitter;
  const recommendations = healthData?.recommendations || [];

  // Map shared devices to health page format
  const deviceHealth = sharedDevices.map((d: any) => ({
    ip: d.ip,
    hostname: d.name,
    device_type: d.kind,
    is_local_device: false,
    latency_ms: d.latency,
    packet_loss_percent: d.loss,
  }));

  const focused = focus ? deviceHealth.find((d: any) => d.ip === focus) : undefined;

  // Calculate averages from real device health data
  let realAvgLatency = 0;
  let realAvgLoss = 0;
  let realTotalDown = throughput?.current_traffic_download_mbps || 0;
  let realTotalUp = throughput?.current_traffic_upload_mbps || 0;

  if (deviceHealth.length > 0) {
    const remoteDevices = deviceHealth.filter((d: any) => !d.is_local_device);
    if (remoteDevices.length > 0) {
      realAvgLatency = remoteDevices.reduce((a: number, d: any) => a + (d.latency_ms || 0), 0) / remoteDevices.length;
      realAvgLoss = remoteDevices.reduce((a: number, d: any) => a + (d.packet_loss_percent || 0), 0) / remoteDevices.length;
    }
  }

  const tips = recommendations.map((r: any) => r.recommendation).filter(Boolean);

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <header>
        <div className="flex items-center justify-between">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-muted-foreground">
              performance
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight">WiFi Health Monitor</h1>
            {focused && (
              <p className="mt-2 text-sm text-muted-foreground">
                Focused on <span className="text-primary">{focused.hostname || focused.ip}</span> ·{" "}
                <Link to="/health" search={{ device: undefined }} className="hover:underline">
                  clear focus
                </Link>
              </p>
            )}
          </div>
          <button
            onClick={() => window.location.reload()}
            className="flex items-center gap-2 rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </header>

      {loading && healthData === null && (
        <div className="mt-6 flex items-center justify-center gap-2 text-muted-foreground">
          <RefreshCw className="h-4 w-4 animate-spin" />
          <span>Loading health data...</span>
        </div>
      )}

      {error && (
        <div className="mt-6 flex items-center gap-2 rounded-md border border-destructive/50 bg-destructive/10 p-4 text-destructive">
          <AlertCircle className="h-4 w-4" />
          <span>Error loading health data: {error}</span>
        </div>
      )}

      {!loading && !error && (
        <>
          <div className="panel mt-6 p-5">
            <div className="flex items-center gap-3">
              <div
                className={cn(
                  "flex h-10 w-10 items-center justify-center rounded-full",
                  healthScore >= 70
                    ? "bg-safe/15 text-safe"
                    : "bg-warn/15 text-warn",
                )}
              >
                <Signal className="h-5 w-5" />
              </div>

              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
                  network overview
                </p>

                <h2 className="mt-1 text-lg font-semibold">
                  {healthScore >= 70
                    ? "Your network is healthy"
                    : "Your network needs attention"}
                </h2>
              </div>
            </div>

            <p className="mt-3 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              {healthScore >= 70
                ? "Your connection is responding normally and no major network problems have been detected."
                : "Your network is showing signs of reduced performance. Check the information below to see what may be causing the problem."}
            </p>
          </div>

          <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat
              icon={<Waves className="h-4 w-4" />}
              label="current traffic"
              value={`${realTotalDown.toFixed(1)} Mbps`}
              sub={throughput?.success
                ? (realTotalDown < 1 && realTotalUp < 1
                  ? "Network currently idle"
                  : `${(throughput.current_traffic_upload_mbps || 0).toFixed(1)} Mbps up`)
                : 'N/A'}
            />
            <Stat
              icon={<Gauge className="h-4 w-4" />}
              label="latency"
              value={`${realAvgLatency.toFixed(0)} ms`}
              sub="average across devices"
              tone={realAvgLatency > 25 ? "warn" : "safe"}
            />
            <Stat
              icon={<TrendingDown className="h-4 w-4" />}
              label="packet loss"
              value={`${realAvgLoss.toFixed(2)}%`}
              sub="average across devices"
              tone={realAvgLoss > 1 ? "warn" : "safe"}
            />
            <Stat
              icon={<Signal className="h-4 w-4" />}
              label="health score"
              value={`${healthScore.toFixed(0)}/100`}
              sub={healthStatus}
              tone={healthScore < 70 ? "warn" : "safe"}
            />
          </div>

          <div className="panel mt-4 p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
                  who is using your network?
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Shows which connected devices are currently generating the most download activity.
                </p>
              </div>
            </div>

            <div className="mt-5 space-y-4">
              {[...sharedDevices]
                .sort((a: any, b: any) => (b.down || 0) - (a.down || 0))
                .map((d: any) => {
                  const usage = d.down || 0;
                  const maxUsage = Math.max(
                    ...sharedDevices.map((device: any) => device.down || 0),
                    1,
                  );
                  const percentage = Math.min((usage / maxUsage) * 100, 100);

                  return (
                    <div key={d.id || d.ip}>
                      <div className="flex items-center justify-between gap-3 text-sm">
                        <div className="min-w-0">
                          <p className="truncate font-medium">
                            {d.name || d.ip}
                          </p>
                          <p className="font-mono text-[10px] text-muted-foreground">
                            {d.ip}
                          </p>
                        </div>

                        <span className="shrink-0 font-mono text-xs">
                          {usage.toFixed(1)} Mbps
                        </span>
                      </div>

                      <div className="mt-2 h-2 overflow-hidden rounded-full bg-muted">
                        <div
                          className="h-full rounded-full bg-primary transition-all duration-500"
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
            </div>

            {sharedDevices.length > 0 && (
              <p className="mt-5 border-t border-border pt-4 text-sm text-muted-foreground">
                <span className="font-medium text-foreground">
                  {([...sharedDevices].sort(
                    (a: any, b: any) => (b.down || 0) - (a.down || 0),
                  )[0]?.name ||
                    [...sharedDevices].sort(
                      (a: any, b: any) => (b.down || 0) - (a.down || 0),
                    )[0]?.ip)}
                </span>{" "}
                is currently using the most bandwidth.
              </p>
            )}
          </div>

          <div className="panel mt-4 p-5">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-primary" />

              <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
                why is your network slow?
              </p>
            </div>

            <div className="mt-4">
              {realAvgLatency > 25 ? (
                <>
                  <p className="text-base font-semibold text-warn">
                    Your connection is experiencing higher-than-normal delay.
                  </p>

                  <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                    The average response time across your connected devices is{" "}
                    <span className="font-medium text-foreground">
                      {realAvgLatency.toFixed(0)} ms
                    </span>
                    . This can make browsing, gaming, or video calls feel slower.
                  </p>
                </>
              ) : realAvgLoss > 1 ? (
                <>
                  <p className="text-base font-semibold text-warn">
                    Your network is losing some data packets.
                  </p>

                  <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                    Packet loss is currently{" "}
                    <span className="font-medium text-foreground">
                      {realAvgLoss.toFixed(2)}%
                    </span>
                    . This can cause buffering, interruptions, or delayed responses.
                  </p>
                </>
              ) : realTotalDown > 50 ? (
                <>
                  <p className="text-base font-semibold text-warn">
                    Your network is currently busy.
                  </p>

                  <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                    Current download traffic is{" "}
                    <span className="font-medium text-foreground">
                      {realTotalDown.toFixed(1)} Mbps
                    </span>
                    . Heavy activity from connected devices may make the network feel
                    slower.
                  </p>
                </>
              ) : (
                <>
                  <p className="text-base font-semibold text-safe">
                    No major network problem detected.
                  </p>

                  <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                    Your latency, packet loss, and current traffic levels are within
                    normal ranges. If something still feels slow, the problem may be
                    specific to the website, application, Wi-Fi signal, or internet
                    service.
                  </p>
                </>
              )}
            </div>
          </div>

          {jitter?.success && jitter.jitter_ms !== null && (
            <div className="mt-4 panel p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
                    jitter measurement
                  </p>
                  <p className="mt-2 text-2xl font-semibold tabular-nums">{jitter.jitter_ms.toFixed(2)} ms</p>
                  <p className="mt-1 text-xs text-muted-foreground">Average latency: {(jitter.avg_latency_ms || 0).toFixed(1)} ms</p>
                </div>
                <div className="text-right">
                  <p className="text-sm text-muted-foreground">Target: Router</p>
                  <p className="text-xs text-muted-foreground">10 pings sent</p>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      <div className="panel mt-4 p-5">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
            network activity over time
          </p>

          <p className="mt-1 text-xs text-muted-foreground">
            See when your network is busy or quiet.
          </p>
        </div>
        <div className="mt-4 h-56">
          {trafficHistory.length === 0 ? (
            <div className="flex h-full items-center justify-center text-muted-foreground">
              <p className="text-sm">Collecting data...</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficHistory}>
                <defs>
                  <linearGradient id="colorDownload" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorUpload" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--safe)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--safe)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="time"
                  tick={{ fontSize: 10 }}
                  stroke="var(--muted-foreground)"
                />
                <YAxis
                  tick={{ fontSize: 10 }}
                  stroke="var(--muted-foreground)"
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'var(--card)',
                    border: '1px solid var(--border)',
                    borderRadius: '6px'
                  }}
                  labelStyle={{ color: 'var(--foreground)' }}
                />
                <Area
                  type="monotone"
                  dataKey="download"
                  stroke="var(--primary)"
                  fillOpacity={1}
                  fill="url(#colorDownload)"
                  name="Download (Mbps)"
                />
                <Area
                  type="monotone"
                  dataKey="upload"
                  stroke="var(--safe)"
                  fillOpacity={1}
                  fill="url(#colorUpload)"
                  name="Upload (Mbps)"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <div className="panel overflow-hidden lg:col-span-2">
          <p className="border-b border-border p-5 pb-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
            devices by health
          </p>
          <table className="w-full text-sm">
            <thead>
              <tr className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="px-5 py-2 text-left font-normal">device</th>
                <th className="px-3 py-2 text-right font-normal">latency</th>
                <th className="px-3 py-2 text-right font-normal">packet loss</th>
                <th className="px-5 py-2 text-right font-normal">type</th>
              </tr>
            </thead>
            <tbody>
              {deviceHealth.map((d: any) => (
                <tr
                  key={d.ip}
                  className={cn(
                    "border-t border-border/60",
                    focus === d.ip && "bg-accent/40",
                  )}
                >
                  <td className="px-5 py-3">
                    <Link
                      to="/defender"
                      search={{ device: d.ip }}
                      className="hover:text-primary"
                    >
                      {d.hostname || d.ip}
                    </Link>
                    <span className="ml-2 font-mono text-[10px] text-muted-foreground">{d.ip}</span>
                    {d.is_local_device && (
                      <span className="ml-2 rounded bg-accent px-1.5 py-0.5 text-[10px] text-muted-foreground">local</span>
                    )}
                  </td>
                  <td className="px-3 py-3 text-right font-mono text-xs">{d.latency_ms !== null ? `${d.latency_ms.toFixed(0)} ms` : 'N/A'}</td>
                  <td className="px-3 py-3 text-right font-mono text-xs">{d.packet_loss_percent !== null ? `${d.packet_loss_percent.toFixed(2)}%` : 'N/A'}</td>
                  <td className="px-5 py-3 text-right font-mono text-xs">{d.device_type || 'Unknown'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel p-5">
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
            recommendations
          </p>
          <ul className="mt-4 space-y-4">
            {tips.map((t: string, i: number) => (
              <li key={i} className="border-l-2 border-primary/60 pl-3 text-sm text-muted-foreground">
                {t}
              </li>
            ))}
          </ul>
          <Link
            to="/assistant"
            search={{ device: undefined, event: undefined }}
            className="mt-6 inline-block text-xs text-primary hover:underline"
          >
            Ask the AI analyst for a full report
          </Link>
        </div>
      </div>
    </div>
  );
}

function Stat({
  icon,
  label,
  value,
  sub,
  tone = "neutral",
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub: string;
  tone?: "neutral" | "safe" | "warn";
}) {
  return (
    <div className="panel p-5">
      <div className="flex items-center gap-2 text-muted-foreground">
        {icon}
        <span className="font-mono text-[10px] uppercase tracking-[0.18em]">{label}</span>
      </div>
      <p
        className={cn(
          "mt-3 text-2xl font-semibold tabular-nums",
          tone === "warn" ? "text-warn" : tone === "safe" ? "text-foreground" : "text-foreground",
        )}
      >
        {value}
      </p>
      <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
    </div>
  );
}
