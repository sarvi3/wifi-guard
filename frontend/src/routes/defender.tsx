import { useState, useEffect, useCallback } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { Activity, Bot, ShieldAlert, ShieldOff, X, Laptop } from "lucide-react";
import { NetworkGraph } from "@/components/NetworkGraph";
import { ThreatConfidence } from "@/components/ThreatConfidence";
import { AttackLab } from "@/components/AttackLab";
import { AnimatedNumber } from "@/components/AnimatedNumber";
import {
  PHASE_LABEL,
  ROUTER_INFO,
  deviceStatus,
  useNetwork,
  type Device,
  type Packet,
} from "@/lib/network-sim";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/defender")({
  validateSearch: (s: Record<string, unknown>) => ({
    device: typeof s["device"] === "string" ? s["device"] : undefined,
  }),
  head: () => ({
    meta: [
      { title: "Threat Defender — Live Network Map | WiFi Guard" },
      {
        name: "description",
        content:
          "Watch packets travel between your devices, zoom into any host, inspect single packets and see ARP spoofing unfold live.",
      },
      { property: "og:title", content: "Threat Defender — Live Network Map" },
      {
        property: "og:description",
        content: "A living map of your WiFi: green, yellow and red packets moving in real time.",
      },
    ],
  }),
  component: Defender,
});

// Common service ports for resolution
const SERVICE_PORTS: Record<number, string> = {
  80: 'HTTP',
  443: 'HTTPS',
  22: 'SSH',
  21: 'FTP',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  110: 'POP3',
  143: 'IMAP',
  993: 'IMAPS',
  995: 'POP3S',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  6379: 'Redis',
  27017: 'MongoDB',
  3389: 'RDP',
  5900: 'VNC',
};

function resolveService(ip: string, port?: number): string {
  if (port && SERVICE_PORTS[port]) {
    return SERVICE_PORTS[port];
  }
  // Check if IP is a common local service
  if (ip === '127.0.0.1' || ip === 'localhost') {
    return 'localhost';
  }
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
    return 'LAN';
  }
  // For external IPs, return a generic service name instead of the IP
  // This prevents creating separate Timeline cards for every destination IP
  return 'internet';
}

function extractPort(ip: string): number | undefined {
  const match = ip.match(/:(\d+)$/);
  return match ? parseInt(match[1] || '0', 10) : undefined;
}

function getDisplayLabel(hostname: string | null, service: string, dst_ip: string): string {
  // Use hostname if available from DNS/TLS/SNI evidence
  if (hostname) {
    // Remove trailing DNS dots
    const cleanHostname = hostname.replace(/\.$/, '');

    // Detect YouTube domains
    if (cleanHostname === 'youtube.com' ||
      cleanHostname === 'www.youtube.com' ||
      cleanHostname.endsWith('.googlevideo.com')) {
      return 'YouTube';
    }

    // Detect verified Google domains
    const googleDomains = [
      'google.com', 'www.google.com', 'mail.google.com', 'drive.google.com',
      'docs.google.com', 'sheets.google.com', 'slides.google.com',
      'calendar.google.com', 'photos.google.com', 'maps.google.com',
      'accounts.google.com', 'payments.google.com', 'cloud.google.com',
      'firebase.google.com', 'gstatic.com', 'googleapis.com',
      'googleusercontent.com', 'googlevideo.com', 'ytimg.com'
    ];

    if (googleDomains.some(domain => cleanHostname === domain || cleanHostname.endsWith('.' + domain))) {
      return 'Google';
    }

    // Keep unknown hostnames as their real hostname
    return cleanHostname;
  }

  // Fallback to generic labels for destinations without hostname
  if (service === 'LAN' || service === 'localhost') {
    return 'Local network';
  }

  if (dst_ip.startsWith('192.168.') || dst_ip.startsWith('10.') || dst_ip.startsWith('172.')) {
    return 'Local network';
  }

  if (dst_ip === '127.0.0.1' || dst_ip === 'localhost') {
    return 'Local network';
  }

  // External destination without hostname - show the destination IP address
  return dst_ip;
}

function aggregatePackets(
  packets: any[],
  selectedDevice: string
): Array<{
  timestamp: string;
  direction: string;
  protocol: string;
  service: string;
  dst_ip: string;
  hostname: string | null;
  count: number;
  totalBytes: number;
}> {
  const aggregated: Map<string, any> = new Map();

  packets.forEach((pkt) => {
    const dstPort = extractPort(pkt.dst_ip || "");
    const service = resolveService(pkt.dst_ip || "", dstPort);

    const direction =
      pkt.src_ip === selectedDevice ? "outbound" : "inbound";

    const hostname = pkt.hostname
      ? String(pkt.hostname)
          .trim()
          .replace(/\.$/, "")
          .toLowerCase()
      : null;

    // Use the SAME label that Timeline displays
    const displayLabel = getDisplayLabel(
      hostname,
      service,
      pkt.dst_ip || ""
    );

    // Group by displayed destination + direction
    const key = `${displayLabel}|${direction}`;

    if (aggregated.has(key)) {
      const existing = aggregated.get(key);

      existing.count += 1;
      existing.totalBytes += Number(pkt.size || 0);

      if (
        pkt.timestamp &&
        new Date(pkt.timestamp).getTime() >
          new Date(existing.timestamp).getTime()
      ) {
        existing.timestamp = pkt.timestamp;
      }

      if (!existing.hostname && hostname) {
        existing.hostname = hostname;
      }
    } else {
      aggregated.set(key, {
        timestamp: pkt.timestamp,
        direction,
        protocol: pkt.protocol || "UNKNOWN",
        service,
        dst_ip: pkt.dst_ip || "",
        hostname,
        count: 1,
        totalBytes: Number(pkt.size || 0),
      });
    }
  });

  return Array.from(aggregated.values())
    .sort(
      (a, b) =>
        new Date(b.timestamp).getTime() -
        new Date(a.timestamp).getTime()
    )
    .slice(0, 25);
}

function getThreatDestinationLabel(event: any): string {
  if (event.hostname) return event.hostname;

  const reason = event.reason || "";

  const match = reason.match(
    /(?:domain detected:|website detected:|hostname detected:)\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i
  );

  if (match?.[1]) {
    return match[1];
  }

  return event.destination_ip || event.source_ip || "Unknown";
}

function Defender() {
  const { device: selected } = Route.useSearch();
  const navigate = useNavigate({ from: "/defender" });
  const { state, allowDevice } = useNetwork();
  const [packet, setPacket] = useState<{ p: Packet; d: Device } | null>(null);

  // Helper function to format bytes appropriately
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return "0 B";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  };

  // Threat monitoring state
  const [threatStatus, setThreatStatus] = useState<any>(null);
  const [threatEvents, setThreatEvents] = useState<any[]>([]);
  const [monitoring, setMonitoring] = useState(false);
  const [activeAlert, setActiveAlert] = useState<any>(null);
  const [lastAlertKey, setLastAlertKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [deviceStats, setDeviceStats] = useState<any>(null);
  const [devicePackets, setDevicePackets] = useState<any[]>([]);
  const [blockedWebsites, setBlockedWebsites] = useState<string[]>([]);
  const [selectedExplanation, setSelectedExplanation] = useState<string | null>(null);
  const [explainingThreat, setExplainingThreat] = useState(false);

  // Fetch threat status
  const fetchThreatStatus = useCallback(async () => {
    try {
      const response = await fetch('https://wifi-guard-production.up.railway.app/threat-status');
      if (response.ok) {
        const data = await response.json();
        setThreatStatus(data);
        // Don't override monitoring state from polling - only set from start/stop
        // setMonitoring(data.monitoring);
      }
    } catch (err) {
      console.error('Failed to fetch threat status:', err);
    }
  }, []);

  // Fetch threat events
  const fetchThreatEvents = useCallback(async () => {
    try {
      const response = await fetch('https://wifi-guard-production.up.railway.app/threat-events?limit=10');
      if (response.ok) {
        const data = await response.json();
        setThreatEvents(data.events || []);
      }
    } catch (err) {
      console.error('Failed to fetch threat events:', err);
    }
  }, []);
  
  const fetchBlockedWebsites = useCallback(async () => {
    try {
      const response = await fetch(
        "https://wifi-guard-production.up.railway.app/blocked-websites"
      );

      if (response.ok) {
        const data = await response.json();
        setBlockedWebsites(data.blocked || []);
      }
    } catch (err) {
      console.error("Failed to fetch blocked websites:", err);
    }
  }, []);

  // Fetch device statistics
  const fetchDeviceStats = useCallback(async (ip: string) => {
    try {
      const response = await fetch(`https://wifi-guard-production.up.railway.app/device-stats?ip=${encodeURIComponent(ip)}`);
      if (response.ok) {
        const data = await response.json();
        // Set deviceStats if the device was found in monitoring data
        // If monitoring is active but device not found, still set deviceStats with empty data
        // to avoid falling back to simulated values
        if (data.stats && data.stats.found !== false) {
          setDeviceStats(data.stats);
          // Also set device packets
          setDevicePackets(data.stats.recent_packets || []);
        } else if (monitoring) {
          // Monitoring is active but device not in captured packets yet
          // Set empty stats to avoid fallback to simulated data
          setDeviceStats({
            ip: ip,
            found: true,
            packet_count: 0,
            bytes_sent: 0,
            bytes_received: 0,
            protocols: {},
            connections: [],
            connection_count: 0,
            last_activity: null,
            threats: 0,
            threat_score: 0,
            severity: "SAFE",
            recent_packets: []
          });
        } else {
          setDeviceStats(null);
        }
      }
    } catch (err) {
      console.error('Failed to fetch device stats:', err);
      setDeviceStats(null);
    }
  }, [monitoring]);

  // Start monitoring
  const startMonitoring = async () => {
    try {
      setLoading(true);
      const response = await fetch('https://wifi-guard-production.up.railway.app/start-monitoring', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (response.ok) {
        const data = await response.json();
        setMonitoring(data.monitoring);
        // Fetch threat status after starting to get initial threat data
        await fetchThreatStatus();
      }
    } catch (err) {
      console.error('Failed to start monitoring:', err);
    } finally {
      setLoading(false);
    }
  };

  // Stop monitoring
  const stopMonitoring = async () => {
    try {
      setLoading(true);
      const response = await fetch('https://wifi-guard-production.up.railway.app/stop-monitoring', {
        method: 'POST',
      });
      if (response.ok) {
        const data = await response.json();
        setMonitoring(data.monitoring);
        await fetchThreatStatus();
      }
    } catch (err) {
      console.error('Failed to stop monitoring:', err);
    } finally {
      setLoading(false);
    }
  };

  const select = (id: string | null) =>
    navigate({ search: { device: id ?? undefined }, replace: true });

  const device =
    selected ? state.devices.find((d) => d.id === selected) : undefined;

  const selectedRouter =
    device?.kind === "router"
      ? device
      : selected === "router"
        ? state.devices.find((d) => d.kind === "router")
        : undefined;

  const isRouter = !!selectedRouter;
  // Poll threat status when monitoring
  useEffect(() => {
    // Always fetch on mount to get current status
    fetchThreatStatus();
    fetchThreatEvents();
    fetchBlockedWebsites();

    let interval: NodeJS.Timeout | null = null;
    if (monitoring) {
      interval = setInterval(() => {
        fetchThreatStatus();
        fetchThreatEvents();
        // Also refresh device stats if a device is selected
        if (selected && selected !== "router" && device) {
          fetchDeviceStats(device.ip);
        }
      }, 2000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [monitoring, fetchThreatStatus, fetchThreatEvents, fetchBlockedWebsites, selected, device, fetchDeviceStats]);

  // Fetch device stats when a device is selected
  useEffect(() => {
    if (selected && selected !== "router" && device && device.ip) {
      fetchDeviceStats(device.ip);
    } else {
      setDeviceStats(null);
    }
  }, [selected, device, fetchDeviceStats]);

  useEffect(() => {
    if (!threatEvents.length) return;

    const latest = threatEvents[0];

    const alertKey = `${latest.timestamp}-${latest.threat_type}-${latest.source_ip}`;

    if (alertKey !== lastAlertKey) {
      setActiveAlert(latest);
      setLastAlertKey(alertKey);
    }
  }, [threatEvents, lastAlertKey]);

  const phaseTone =
    state.phase === "intercept"
      ? "border-danger/50 bg-danger/10 text-danger"
      : state.phase === "suspicious" || state.phase === "recon"
        ? "border-warn/50 bg-warn/10 text-warn"
        : state.phase === "defense" || state.phase === "recovered"
          ? "border-safe/40 bg-safe/10 text-safe"
          : "border-border bg-card text-muted-foreground";

  const explainThreat = async (device: any) => {
    const deviceThreat = threatEvents.find(
      (event) =>
        event.source_ip === device.ip ||
        event.destination_ip === device.ip ||
        event.device_ip === device.ip
    );

    if (!deviceThreat) {
      setSelectedExplanation("No active threat found for this device.");
      return;
    }

    setExplainingThreat(true);
    setSelectedExplanation("Generating AI explanation...");

    try {
      const response = await fetch(
        "https://wifi-guard-production.up.railway.app/threat-explanation",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            threat: deviceThreat,
          }),
        }
      );

      const data = await response.json();

      setSelectedExplanation(
        data.explanation ||
          data.error ||
          "AI explanation is currently unavailable."
      );
    } catch (error) {
      console.error(error);
      setSelectedExplanation(
        "AI explanation is currently unavailable."
      );
    } finally {
      setExplainingThreat(false);
    }
  };

  return (
    <div className="flex h-[calc(100vh-3.5rem)] flex-col overflow-hidden">
      {activeAlert && (
        <div className="absolute right-6 top-20 z-50 w-80 rounded-lg border border-warn/50 bg-card p-4 shadow-lg">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-warn" />
              <p className="font-semibold text-warn">
                {activeAlert.threat_type === "suspicious_website"
                  ? "Suspicious website detected"
                  : "Threat detected"}
              </p>
            </div>

            <button
              onClick={() => setActiveAlert(null)}
              className="text-muted-foreground hover:text-foreground"
              aria-label="Close alert"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <p className="mt-3 text-sm text-foreground">
            {activeAlert.reason}
          </p>

          <p className="mt-1 font-mono text-[10px] text-muted-foreground">
            Destination: {getThreatDestinationLabel(activeAlert)}
          </p>

          <div className="mt-4 flex gap-2">
            <button
              type="button"
              onClick={() => {
                if (!activeAlert) return;

                navigate({
                  to: "/assistant",
                  search: {
                    device: selected,
                    event: activeAlert.reason,
                  },
                });
              }}
              className="flex-1 rounded-md bg-primary py-2 text-xs font-medium text-primary-foreground"
            >
              Ask AI
            </button>

            
            <button
              type="button"
              onClick={async () => {
                const destinationIp = activeAlert?.destination_ip;

                if (!destinationIp) {
                  alert("No destination IP found");
                  return;
                }

                try {
                  const blockDomain =
                    activeAlert?.hostname &&
                    !/^\d{1,3}(\.\d{1,3}){3}$/.test(activeAlert.hostname) &&
                    !activeAlert.hostname.includes(":")
                      ? activeAlert.hostname
                      : getThreatDestinationLabel(activeAlert);
                  const response = await fetch("https://wifi-guard-production.up.railway.app/block-website", {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                      domain: blockDomain,
                      destination_ip: destinationIp,
                    }),
                  });

                  const data = await response.json();

                  if (!response.ok || !data.success) {
                    alert(`Block failed: ${data.error || "Unknown error"}`);
                    return;
                  }

                  alert(`Blocked: ${destinationIp}`);
                  await fetchBlockedWebsites();
                  setActiveAlert(null);
                } catch (err) {
                  alert(`Block request failed: ${err}`);
                }
              }}
              className="rounded-md border border-danger/50 px-4 py-2 text-xs text-danger"
            >
              Block
            </button>

            <button
              type="button"
              onClick={async () => {
                const destinationIp = activeAlert?.destination_ip;

                if (!destinationIp) {
                  alert("No destination IP found");
                  return;
                }

                try {
                  const response = await fetch(
                    "https://wifi-guard-production.up.railway.app/unblock-website",
                    {
                      method: "POST",
                      headers: {
                        "Content-Type": "application/json",
                      },
                      body: JSON.stringify({
                        destination_ip: destinationIp,
                      }),
                    }
                  );

                  const data = await response.json();

                  if (!response.ok || !data.success) {
                    alert(`Unblock failed: ${data.error || "Unknown error"}`);
                    return;
                  }

                  alert(`Unblocked: ${destinationIp}`);
                } catch (err) {
                  alert(`Unblock request failed: ${err}`);
                }
              }}
              className="rounded-md border border-safe/50 px-4 py-2 text-xs text-safe"
            >
              Unblock Website
            </button>
          </div>
        </div>
      )}
      {blockedWebsites.length > 0 && (
        <div className="absolute bottom-6 right-6 z-40 w-80 rounded-lg border border-danger/40 bg-card p-4 shadow-lg">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground">
              Blocked Websites
            </h3>
            <ShieldOff className="h-4 w-4 text-danger" />
          </div>

          <div className="space-y-2">
            {blockedWebsites.map((ip) => (
              <div
                key={ip}
                className="flex items-center gap-3 rounded-md border border-border bg-background p-2"
              >
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-foreground">
                  {ip}
                </span>

                <button
                  type="button"
                  onClick={async () => {
                    try {
                      const response = await fetch(
                        "https://wifi-guard-production.up.railway.app/unblock-website",
                        {
                          method: "POST",
                          headers: {
                            "Content-Type": "application/json",
                          },
                          body: JSON.stringify({
                            destination_ip: ip,
                          }),
                        }
                      );

                      const data = await response.json();

                      if (!response.ok || !data.success) {
                        alert(`Unblock failed: ${data.error || "Unknown error"}`);
                        return;
                      }

                      await fetchBlockedWebsites();
                    } catch (err) {
                      alert(`Unblock request failed: ${err}`);
                    }
                  }}
                  className="shrink-0 rounded-md border border-safe/50 px-2 py-1 text-[10px] text-safe"
                >
                  Unblock
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
      <div className="flex flex-1 overflow-hidden min-w-0 pb-32">
        <div className="relative min-w-0 flex-1 overflow-hidden">
          <div className="pointer-events-none absolute left-6 top-5 z-10">
            <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-muted-foreground">
              threat defender
            </p>
            <h1 className="mt-1 text-xl font-semibold tracking-tight">Live network map</h1>
            <p className="mt-1 max-w-xs text-xs text-muted-foreground">
              Click any device, the router, or a moving packet to inspect it.
            </p>
          </div>

          <div className="absolute right-6 top-5 z-10 flex items-center gap-3">
            <button
              onClick={monitoring ? stopMonitoring : startMonitoring}
              disabled={loading}
              className={cn(
                "rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-[0.18em] transition-colors",
                monitoring
                  ? "border-warn/50 bg-warn/10 text-warn hover:bg-warn/20"
                  : "border-safe/40 bg-safe/10 text-safe hover:bg-safe/20",
                loading && "opacity-50 cursor-not-allowed",
              )}
            >
              {loading ? "loading..." : monitoring ? "stop monitoring" : "start monitoring"}
            </button>
            {threatStatus && (
              <span
                className={cn(
                  "rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-[0.18em]",
                  threatStatus.severity === "HIGH RISK"
                    ? "border-danger/50 bg-danger/10 text-danger"
                    : threatStatus.severity === "WARNING"
                      ? "border-warn/50 bg-warn/10 text-warn"
                      : "border-safe/40 bg-safe/10 text-safe",
                )}
              >
                {threatStatus.severity} · {threatStatus.threat_score}
              </span>
            )}
            <span
              className={cn(
                "rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-[0.18em] transition-colors",
                phaseTone,
              )}
            >
              stage · {PHASE_LABEL[state.phase]}
            </span>
            {state.firewall === "engaged" && (
              <span className="flex items-center gap-1.5 rounded-full border border-safe/40 bg-safe/10 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.18em] text-safe">
                <ShieldOff className="h-3 w-3" />
                blocked <AnimatedNumber value={state.blocked} />
              </span>
            )}
          </div>

          <div className="absolute bottom-4 left-6 z-10 flex gap-4 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <i className="h-2 w-2 rounded-full bg-safe" /> normal
            </span>
            <span className="flex items-center gap-1.5">
              <i className="h-2 w-2 rounded-full bg-warn" /> suspicious
            </span>
            <span className="flex items-center gap-1.5">
              <i className="h-2 w-2 rounded-full bg-danger" /> malicious
            </span>
            <span className="flex items-center gap-1.5">
              <i className="h-2 w-2 rounded-full border border-safe" /> blocked
            </span>
          </div>

          <NetworkGraph
            selected={selected ?? null}
            onSelect={select}
            onPacket={(p, d) => setPacket({ p, d })}
          />
        </div>

        {selected && (
          <aside className="w-80 shrink-0 overflow-y-auto border-l border-border bg-card/60 p-5 wg-slide-in">
            <div className="flex items-start justify-between">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
                  {isRouter ? "gateway" : "device"}
                </p>
                <h2 className="mt-1 text-lg font-semibold">
                  {isRouter
                    ? selectedRouter?.name ?? ROUTER_INFO.name
                    : device?.name}
                </h2>
                {device && (
                  <p className="mt-1 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                    <i
                      className={cn(
                        "h-1.5 w-1.5 rounded-full",
                        deviceStatus(device) === "threatened"
                          ? "bg-danger wg-blip"
                          : deviceStatus(device) === "busy"
                            ? "bg-warn"
                            : "bg-safe",
                      )}
                    />
                    {device.blockedByUser
                      ? "blocked"
                      : deviceStatus(device) === "threatened"
                        ? "under threat"
                        : deviceStatus(device) === "busy"
                          ? "heavy traffic"
                          : "normal"}
                  </p>
                )}
              </div>
              <button
                onClick={() => select(null)}
                className="rounded-md p-1 text-muted-foreground hover:text-foreground"
                aria-label="Close panel"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {isRouter ? (
              <dl className="mt-5 space-y-3">
                <Row k="Gateway IP" v={selectedRouter?.ip ?? ROUTER_INFO.ip} />
                <Row k="MAC" v={selectedRouter?.mac ?? ROUTER_INFO.mac} />
                <Row k="Vendor" v={selectedRouter?.vendor ?? ROUTER_INFO.vendor} />
                <Row k="SSID" v={ROUTER_INFO.ssid} />
                <Row
                  k="Throughput"
                  v={`${state.devices.reduce((a, d) => a + d.down, 0).toFixed(1)} Mbps`}
                />
                <Row k="Active devices" v={String(state.devices.filter((d) => d.online).length)} />
                {threatStatus && (
                  <>
                    <Row k="Packets captured" v={String(threatStatus.packet_count)} />
                    <Row
                      k="Threats detected"
                      v={String(threatStatus.total_threats)}
                      tone={threatStatus.total_threats > 0 ? "danger" : undefined}
                    />
                    <Row
                      k="Threat score"
                      v={`${threatStatus?.threat_score ?? 0}%`}
                      tone={
                        threatStatus?.severity === "HIGH RISK"
                          ? "danger"
                          : threatStatus?.severity === "WARNING"
                            ? "warn"
                            : undefined
                      }
                    />

                    <Row
                      k="Severity"
                      v={threatStatus?.severity ?? "SAFE"}
                      tone={
                        threatStatus?.severity === "HIGH RISK"
                          ? "danger"
                          : threatStatus?.severity === "WARNING"
                            ? "warn"
                            : undefined
                      }
                    />
                  </>
                )}
                <Row
                  k="Firewall"
                  v={state.firewall === "engaged" ? "Engaged — blocking" : "Active"}
                  tone={state.firewall === "engaged" ? "warn" : undefined}
                />
                <Row k="Frames blocked" v={String(state.blocked)} />
              </dl>
            ) : device ? (
              <>
                <dl className="mt-5 space-y-3">
                  <Row k="IP address" v={deviceStats?.ip || device.ip} />
                  <Row k="MAC" v={deviceStats?.mac || device.mac} />
                  <Row k="Vendor" v={device.vendor} />
                  {deviceStats ? (
                    <>
                      <Row k="Packets" v={String(deviceStats.packet_count ?? 0)} />
                      <Row k="Incoming" v={formatBytes(deviceStats.bytes_received || 0)} />
                      <Row k="Outgoing" v={formatBytes(deviceStats.bytes_sent || 0)} />
                      <Row k="Connections" v={String(deviceStats.connection_count ?? 0)} />
                      <Row k="Protocols" v={deviceStats.protocols ? Object.keys(deviceStats.protocols).join(", ") : "None"} />
                      <Row k="Last activity" v={deviceStats.last_activity ? new Date(deviceStats.last_activity).toLocaleTimeString() : "Never"} />
                      <Row
                        k="Threats"
                        v={(deviceStats.threats || 0) > 0 ? `${deviceStats.threats} flagged` : "None"}
                        tone={(deviceStats.threats || 0) > 0 ? "danger" : undefined}
                      />
                      <Row
                        k="Threat score"
                        v={`${threatStatus?.threat_score ?? state.threat}%`}
                        tone={threatStatus?.severity === "HIGH RISK" || state.status === "HIGH RISK" ? "danger" : threatStatus?.severity === "WARNING" || state.status === "WARNING" ? "warn" : undefined}
                      />
                      <Row
                        k="Severity"
                        v={threatStatus?.severity ?? state.status}
                        tone={threatStatus?.severity === "HIGH RISK" || state.status === "HIGH RISK" ? "danger" : threatStatus?.severity === "WARNING" || state.status === "WARNING" ? "warn" : undefined}
                      />
                    </>
                  ) : (
                    <>
                      <Row k="Packets/sec" v={String(device.pps)} />
                      <Row k="Incoming" v={`${device.down.toFixed(1)} Mbps`} />
                      <Row k="Outgoing" v={`${device.up.toFixed(1)} Mbps`} />
                      <Row k="Connections" v={String(device.connections)} />
                      <Row k="Latency" v={`${device.latency.toFixed(0)} ms`} />
                      <Row k="Packet loss" v={`${device.loss.toFixed(2)}%`} />
                      <Row
                        k="Threats"
                        v={device.threats ? `${device.threats} flagged` : "None"}
                        tone={device.threats ? "danger" : undefined}
                      />
                    </>
                  )}
                </dl>

                {device.hostile && (
                  <p className="mt-4 rounded-md border border-danger/40 bg-danger/10 p-3 text-xs text-danger">
                    This host is claiming an address it does not own. Traffic from the affected
                    device is being intercepted.
                  </p>
                )}

                {device.blockedByUser && (
                  <div className="mt-4 rounded-md border border-border bg-background/60 p-3 text-xs text-muted-foreground">
                    You blocked this device, so it can no longer send or receive.
                    <button
                      onClick={() => allowDevice(device.id)}
                      className="mt-2 w-full rounded-md border border-border py-1.5 text-xs transition-colors hover:bg-accent"
                    >
                      Allow back on the network
                    </button>
                  </div>
                )}

                <div className="mt-5 flex flex-col gap-2">
                  {selectedExplanation && (
                    <div className="mt-3 rounded-md border border-primary/30 bg-primary/5 p-3">
                      <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                        Live Explanation
                      </p>

                      <p className="mt-2 text-xs leading-relaxed text-foreground">
                        {selectedExplanation}
                      </p>
                    </div>
                  )}
                  <button
                    type="button"
                    onClick={() => explainThreat(device)}
                    disabled={explainingThreat}
                    className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-xs font-medium text-primary-foreground transition-opacity hover:opacity-90"
                  >
                    <Bot className="h-3.5 w-3.5" />
                    {explainingThreat ? "Analyzing..." : "Explain with AI"}
                  </button>
                  <Link
                    to="/health"
                    search={{ device: device.id }}
                    className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-xs transition-colors hover:bg-accent"
                  >
                    <Activity className="h-3.5 w-3.5" /> Performance details
                  </Link>
                </div>
              </>
            ) : null}



          </aside>
        )}
      </div>

      {/* event timeline - separate independent section */}
      <div className="fixed bottom-0 left-[222px] right-0 z-20 flex h-32 flex-col border-t border-border bg-card/40">
        <div className="flex items-center gap-2 px-6 pt-3 shrink-0">
          <ShieldAlert className="h-3.5 w-3.5 text-muted-foreground" />
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
            timeline
          </p>
          {threatStatus && (
            <span className="font-mono text-[10px] text-muted-foreground">
              · {threatStatus.total_threats} threats · {threatStatus.packet_count} packets
            </span>
          )}
        </div>
        <div className="flex-1 overflow-x-auto overflow-y-auto px-6 pt-3 pb-6">
          <div className="flex w-max flex-row flex-nowrap gap-3">
            {monitoring && selected && devicePackets.length > 0 ? (
              (() => {
                const aggregated = aggregatePackets(devicePackets, selected);

                return aggregated.map((agg: any, idx: number) => (
                  <div
                    key={idx}
                    className="w-56 shrink-0 rounded-md border border-border bg-background/60 p-3"
                  >
                    <div className="flex items-center gap-2">
                      <p className="font-mono text-[10px] text-muted-foreground">
                        {agg.timestamp
                          ? new Date(agg.timestamp).toLocaleTimeString("en-US", {
                            hour: "numeric",
                            minute: "2-digit",
                          })
                          : "--:--"}
                      </p>

                      <span className="text-[10px] text-muted-foreground">→</span>

                      <div className="flex items-center gap-1.5 min-w-0">
                        <Laptop className="h-3 w-3 text-primary shrink-0" />
                        <p className="text-xs font-medium truncate">{selected}</p>
                      </div>
                    </div>

                    <p className="mt-1 text-xs font-medium text-foreground truncate">
                      {getDisplayLabel(agg.hostname, agg.service, agg.dst_ip)}
                    </p>

                    <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
                      <span>
                        {agg.direction === "outbound" ? "Sent data" : "Received data"}
                      </span>
                      <span>·</span>
                      <span>{agg.count} packets</span>
                      <span>·</span>
                      <span className="font-mono">
                        {formatBytes(agg.totalBytes)}
                      </span>
                    </div>
                  </div>
                ));
              })()
            ) : monitoring && threatEvents.length > 0 ? (
              threatEvents.map((e, idx) => (
                <div
                  key={idx}
                  className={cn(
                    "min-w-52 shrink-0 rounded-md border p-3",
                    e.severity === "danger"
                      ? "border-danger/50"
                      : e.severity === "warn"
                        ? "border-warn/50"
                        : "border-border",
                  )}
                >
                  <p className="font-mono text-[10px] text-muted-foreground">
                    {new Date(e.timestamp).toLocaleTimeString()} · {e.threat_type}
                  </p>

                  <p className="mt-1 text-xs font-medium truncate">
                    {e.reason}
                  </p>

                  <p className="mt-0.5 line-clamp-2 text-[11px] text-muted-foreground">
                    {getThreatDestinationLabel(e)} · {e.source_ip}
                  </p>
                </div>
              ))
            ) : (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                {selected
                  ? "No activity for this device yet"
                  : monitoring
                    ? "Monitoring for threats..."
                    : "Start monitoring to detect threats"}
              </div>
            )}
          </div>
        </div>

        {packet && (
          <div
            className="fixed inset-0 z-30 flex items-center justify-center bg-background/70 p-4 backdrop-blur-sm"
            onClick={() => setPacket(null)}
          >
            <div
              className="panel w-full max-w-sm p-5 wg-scale-in"
              onClick={(e) => e.stopPropagation()}
              role="dialog"
              aria-label="Packet detail"
            >
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
                    packet #{packet.p.id}
                  </p>
                  <h3 className="mt-1 text-base font-semibold">
                    {packet.p.protocol} · {packet.p.size} bytes
                  </h3>
                </div>
                <span
                  className={cn(
                    "rounded-full px-2 py-0.5 font-mono text-[10px] uppercase",
                    packet.p.verdict === "malicious"
                      ? "bg-danger/15 text-danger"
                      : packet.p.verdict === "suspicious"
                        ? "bg-warn/15 text-warn"
                        : "bg-safe/15 text-safe",
                  )}
                >
                  {packet.p.blocked ? "blocked" : packet.p.verdict}
                </span>
              </div>
              <dl className="mt-4 space-y-3">
                <Row
                  k="Source"
                  v={packet.p.dir === "up" ? `${packet.d.ip} (${packet.d.name})` : ROUTER_INFO.ip}
                />
                <Row
                  k="Destination"
                  v={packet.p.dir === "up" ? ROUTER_INFO.ip : `${packet.d.ip} (${packet.d.name})`}
                />
                <Row k="Protocol" v={packet.p.protocol} />
                <Row k="Size" v={`${packet.p.size} bytes`} />
                <Row k="Direction" v={packet.p.dir === "up" ? "device → gateway" : "gateway → device"} />
                <Row k="Reason" v={packet.p.reason} />
                <Row
                  k="Disposition"
                  v={packet.p.blocked ? "Dropped by defense" : "Delivered"}
                  tone={packet.p.blocked ? "warn" : undefined}
                />
              </dl>
              <p className="mt-4 rounded-md border border-border bg-background/60 p-3 text-xs leading-relaxed text-muted-foreground">
                <span className="text-primary">AI: </span>
                {packet.p.verdict === "malicious"
                  ? "This frame asserts ownership of an address it has no right to. Believing it would place the attacker between this device and the internet, so it is rejected on sight while defense is engaged."
                  : packet.p.verdict === "suspicious"
                    ? `This ${packet.p.protocol} frame does not match the traffic shape ${packet.d.name} normally produces. It is being watched, but on its own it is not proof of an attack.`
                    : `A routine ${packet.p.protocol} frame between ${packet.d.name} and the gateway. Size, timing and destination all match this device's learned behaviour.`}
              </p>
              <button
                onClick={() => setPacket(null)}
                className="mt-4 w-full rounded-md border border-border py-2 text-xs transition-colors hover:bg-accent"
              >
                Close
              </button>
            </div>
          </div>
        )}
        </div>
      </div>
      );
}

      function Row({k, v, tone}: {k: string; v: string; tone?: "danger" | "warn" | undefined }) {
  return (
      <div className="flex items-baseline justify-between gap-4">
        <dt className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{k}</dt>
        <dd
          className={cn(
            "text-right font-mono text-xs",
            tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : "text-foreground",
          )}
        >
          {v}
        </dd>
      </div>
      );
}
