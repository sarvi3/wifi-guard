import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { scanNetwork, type Device as ApiDevice } from "./api";

export type Verdict = "normal" | "suspicious" | "malicious";

export type DeviceKind = "router" | "laptop" | "phone" | "tv" | "printer" | "camera" | "unknown";

/** The story stages an attack moves through. */
export type Phase = "calm" | "recon" | "suspicious" | "intercept" | "defense" | "recovered";

export type AttackType = "arp" | "mitm" | "eviltwin" | "dns";

export type Trend = "stable" | "falling" | "recovering";

export type DeviceStatus = "normal" | "busy" | "threatened";

export interface Device {
  id: string;
  name: string;
  kind: DeviceKind;
  ip: string;
  mac: string;
  vendor: string;
  angle: number;
  /** relative traffic weight 0..1, drives layout emphasis */
  weight: number;
  down: number; // Mbps
  up: number; // Mbps
  latency: number; // ms
  loss: number; // %
  signal: number; // %
  pps: number;
  connections: number;
  threats: number;
  hostile: boolean;
  online: boolean;
  trusted: boolean;
  blockedByUser: boolean;
}

export interface Packet {
  id: number;
  deviceId: string;
  dir: "up" | "down";
  progress: number;
  speed: number;
  verdict: Verdict;
  protocol: string;
  size: number;
  reason: string;
  /** set when host-side defense rejects the frame mid-flight */
  blocked: boolean;
  blockAt: number;
}

export interface NetEvent {
  id: number;
  t: number;
  time: string;
  label: string;
  detail: string;
  severity: "info" | "warn" | "danger" | "good";
  deviceId?: string | undefined;
  phase: Phase;
}

/** A line in the AI analyst's live feed. */
export interface AiNote {
  id: number;
  time: string;
  text: string;
  tone: "info" | "warn" | "danger" | "good";
}

export interface Alert {
  id: number;
  title: string;
  detail: string;
  deviceId: string;
  time: string;
}

export type Status = "SAFE" | "WARNING" | "HIGH RISK";

export interface Sample {
  t: number;
  down: number;
  up: number;
  latency: number;
  loss: number;
}

export interface NetState {
  devices: Device[];
  packets: Packet[];
  events: NetEvent[];
  notes: AiNote[];
  alerts: Alert[];
  history: Sample[];
  threat: number;
  threatTarget: number;
  trend: Trend;
  status: Status;
  phase: Phase;
  attackActive: boolean;
  attackType: AttackType | null;
  paused: boolean;
  lastScan: number;
  scanning: boolean;
  scanProgress: number;
  firewall: "active" | "engaged";
  blocked: number;
  narration: string;
  hasScanned: boolean; // Track if a real scan has been performed
}

const PROTOCOLS = ["TCP", "UDP", "HTTPS", "DNS", "mDNS", "QUIC", "ARP"];

export const PHASE_LABEL: Record<Phase, string> = {
  calm: "Baseline",
  recon: "Reconnaissance",
  suspicious: "Suspicious",
  intercept: "Threat",
  defense: "Defense",
  recovered: "Recovered",
};

export const PHASE_ORDER: Phase[] = [
  "calm",
  "recon",
  "suspicious",
  "intercept",
  "defense",
  "recovered",
];

export const ATTACKS: Array<{
  id: AttackType;
  name: string;
  blurb: string;
  available: boolean;
}> = [
    {
      id: "arp",
      name: "ARP Spoof",
      blurb: "A rogue host claims the gateway address to sit between you and the internet.",
      available: true,
    },
    {
      id: "mitm",
      name: "Man in the Middle",
      blurb: "Traffic is relayed through an attacker so it can be read and rewritten.",
      available: true,
    },
    {
      id: "eviltwin",
      name: "Evil Twin AP",
      blurb: "A cloned access point with your SSID lures devices into re-associating.",
      available: true,
    },
    {
      id: "dns",
      name: "DNS Spoof",
      blurb: "Forged DNS answers point trusted names at attacker-controlled addresses.",
      available: true,
    },
  ];

function seedDevices(): Device[] {
  const base: Array<Partial<Device> & { id: string; name: string; kind: DeviceKind }> = [
    {
      id: "laptop",
      name: "Workstation",
      kind: "laptop",
      ip: "192.168.1.24",
      mac: "A4:83:E7:1C:90:2B",
      vendor: "Apple Inc.",
      weight: 0.9,
    },
    {
      id: "phone",
      name: "Pixel 9",
      kind: "phone",
      ip: "192.168.1.31",
      mac: "F0:B4:29:7D:11:C4",
      vendor: "Google LLC",
      weight: 0.45,
    },
    {
      id: "tv",
      name: "Living Room TV",
      kind: "tv",
      ip: "192.168.1.42",
      mac: "8C:79:F5:AA:31:07",
      vendor: "Samsung Electronics",
      weight: 1,
    },
    {
      id: "printer",
      name: "Office Printer",
      kind: "printer",
      ip: "192.168.1.55",
      mac: "00:1B:A9:44:2E:10",
      vendor: "Brother Industries",
      weight: 0.12,
    },
    {
      id: "camera",
      name: "Porch Camera",
      kind: "camera",
      ip: "192.168.1.63",
      mac: "B0:C5:54:0F:88:D1",
      vendor: "D-Link Corp.",
      weight: 0.35,
    },
    {
      id: "unknown",
      name: "Unrecognized Host",
      kind: "unknown",
      ip: "192.168.1.77",
      mac: "DE:AD:1F:22:9B:5E",
      vendor: "Unknown vendor",
      weight: 0.2,
      trusted: false,
    },
  ];

  return base.map((d, i) => ({
    angle: (i / base.length) * Math.PI * 2 - Math.PI / 2,
    down: 0,
    up: 0,
    latency: 0,
    loss: 0,
    signal: 0,
    pps: 0,
    connections: 0,
    threats: 0,
    hostile: false,
    online: true,
    trusted: true,
    blockedByUser: false,
    weight: 0.4,
    ip: "",
    mac: "",
    vendor: "",
    ...d,
  })) as Device[];
}

const fmtTime = (d = new Date()) =>
  d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

const CALM_NARRATION =
  "The network is behaving normally. Traffic is dominated by streaming from the Living Room TV and encrypted browsing from the Workstation. No ARP anomalies, no unexpected gateway changes, and every device is answering with its known hardware address.";

interface Step {
  at: number;
  phase: Phase;
  threat: number;
  label: string;
  detail: string;
  severity: NetEvent["severity"];
  deviceId?: string;
  note: string;
  narration: string;
}
interface ArpAttackContext {
  victimId: string;
  victimName: string;
  victimIp: string;
  gatewayIp: string;
  attackerId: string;
  attackerIp: string;
}
function script(
  type: AttackType,
  arpContext?: ArpAttackContext,
  victimId?: string,
  attackerId?: string,): Step[] {
  const common = (
    over: Omit<Partial<Step>, "deviceId"> &
      Pick<Step, "at" | "phase" | "threat"> & {
        deviceId?: string | undefined;
      },
  ): Step => {
    const { deviceId, ...rest } = over;

    return {
      label: "",
      detail: "",
      severity: "info",
      note: "",
      narration: "",
      ...rest,
      ...(deviceId !== undefined ? { deviceId } : {}),
    };
  };
  if (type === "arp") {
    const ctx: ArpAttackContext = arpContext ?? {
      victimId: "laptop",
      victimName: "Workstation",
      victimIp: "192.168.1.24",
      gatewayIp: "192.168.1.1",
      attackerId: "unknown",
      attackerIp: "192.168.1.77",
    };

    return [
      common({
        at: 0,
        phase: "recon",
        threat: 84,
        label: "ARP request burst",
        detail: "Someone is scanning your Wi-Fi network to discover connected devices", severity: "warn",
        deviceId: ctx.attackerId,
        note: `Unusual ARP request volume from ${ctx.attackerIp}. Mapping the subnet is normally a precursor to a targeted attack.`,
        narration:
          `A simulated rogue host has started sweeping the subnet with ARP requests. Nothing has been redirected yet, but this is how an attacker works out which devices exist before picking a target.`,
      }),

      common({
        at: 3,
        phase: "suspicious",
        threat: 61,
        label: "Suspicious ARP response",
        detail: "A device is pretending to be your Wi-Fi gateway. This may be an attempt to intercept traffic", severity: "warn",
        deviceId: ctx.attackerId,
        note: `Suspicious ARP replies detected from ${ctx.attackerIp}. Threat Confidence is decreasing while the gateway claim is verified.`,
        narration:
          `An unsolicited ARP response arrived from the simulated rogue host claiming the gateway address ${ctx.gatewayIp}. This is the classic opening move of ARP spoofing. Threat Confidence is falling while the claim is verified.`,
      }),

      common({
        at: 6.5,
        phase: "intercept",
        threat: 28,
        label: "Gateway MAC changed",
        detail: "Your traffic is being redirected through the suspicious device. WiFi Guard detected the change", severity: "danger",
        deviceId: ctx.victimId,
        note: `The gateway MAC changed unexpectedly for ${ctx.victimName}. Traffic is being pulled through ${ctx.attackerIp}, creating a simulated man-in-the-middle position.`,
        narration:
          `The gateway hardware address changed unexpectedly for ${ctx.victimName}. Its traffic is now being pulled through the simulated rogue host instead of the real router. Threat Confidence has dropped into high risk.`,
      }),

      common({
        at: 10.5,
        phase: "defense",
        threat: 74,
        label: "Defense activated",
        detail: "WiFi Guard blocked the suspicious connection and restored the gateway path", severity: "good",
        note: `Host-side protection ignored the forged ARP entry and pinned the genuine gateway. Malicious frames are being dropped.`,
        narration:
          `Host-side protection has rejected the malicious ARP entry and pinned the real gateway address. Poisoned frames are now dropped at the host while the simulated rogue device stays under observation.`,
      }),

      common({
        at: 15,
        phase: "recovered",
        threat: 92,
        label: "Network stabilised",
        detail: "The suspicious device was removed and normal network communication resumed", severity: "good",
        note: "Normal communication has resumed. Threat Confidence is recovering toward baseline.",
        narration: CALM_NARRATION,
      }),
    ];
  }

  if (type === "mitm") {
    return [
      common({
        at: 0,
        phase: "recon",
        threat: 82,
        label: "Relay host detected",
        detail: "Someone is forwarding traffic through a suspicious device on your Wi-Fi network", severity: "warn",
        deviceId: attackerId,
        note: "An unrecognized host started forwarding frames for other devices. That is relay behaviour, not client behaviour.",
        narration:
          "An unrecognized host has started forwarding traffic for devices other than itself. Legitimate clients do not relay their neighbours' frames.",
      }),
      common({
        at: 3,
        phase: "suspicious",
        threat: 58,
        label: "TLS session renegotiated",
        detail: "Your encrypted connection changed unexpectedly, which may indicate someone is sitting between you and the internet", severity: "warn",
        deviceId: victimId,
        note: "Encrypted sessions from the selected device were renegotiated with an unfamiliar certificate chain. Threat Confidence is decreasing.", narration:
          "Encrypted sessions from the Workstation were torn down and re-established against an unfamiliar certificate chain, which is what happens when something interposes itself in the path.",
      }),
      common({
        at: 6.5,
        phase: "intercept",
        threat: 24,
        label: "Traffic relayed off-path",
        detail: "Your traffic is passing through the suspicious device before reaching the real gateway", severity: "danger",
        deviceId: victimId,
        note: "Traffic from the selected device is transiting the suspicious host. Content may be readable and rewritable by the attacker.",
        narration:
          "All Workstation traffic is now travelling through the hostile host before it reaches the router. In this position an attacker can read and rewrite anything not end-to-end encrypted.",
      }),
      common({
        at: 10.5,
        phase: "defense",
        threat: 72,
        label: "Defense activated",
        detail: "WiFi Guard blocked the suspicious relay and restored the direct gateway path", severity: "good",
        note: "Relayed frames are being dropped and the route is pinned back to the genuine gateway.",
        narration:
          "The relay path has been cut. Frames arriving from the hostile host are dropped and the route is pinned back to the genuine gateway.",
      }),
      common({
        at: 15,
        phase: "recovered",
        threat: 92,
        label: "Network stabilised",
        detail: "Your connections are communicating directly with the real gateway again", severity: "good",
        note: "Sessions were re-established directly with the gateway. Threat Confidence is recovering.",
        narration: CALM_NARRATION,
      }),
    ];
  }

  if (type === "eviltwin") {
    return [
      common({
        at: 0,
        phase: "recon",
        threat: 83,
        label: "Duplicate SSID beacon",
        detail: "Someone created a second Wi-Fi network using the same network name", severity: "warn",
        deviceId: attackerId,
        note: "A second access point is beaconing your SSID with a different BSSID. Evil-twin behaviour.",
        narration:
          "A second access point has begun beaconing the GUARDNET-5G name from a different hardware address. Devices cannot tell the two apart by name alone.",
      }),
      common({
        at: 3,
        phase: "suspicious",
        threat: 57,
        label: "Deauthentication frames",
        detail: "Devices are being pushed away from the real Wi-Fi network", severity: "warn",
        deviceId: victimId,
        note: "Deauth frames are pushing clients off the real access point so they re-associate with the clone.",
        narration:
          "Deauthentication frames are knocking clients off the genuine access point. Each disconnect is an opportunity for the clone to win the re-association.",
      }),
      common({
        at: 6.5,
        phase: "intercept",
        threat: 26,
        label: "Client associated to clone",
        detail: "A device connected to the suspicious Wi-Fi network instead of the real one", severity: "danger",
        deviceId: victimId,
        note: "Pixel 9 associated with the rogue access point. Its traffic is leaving through attacker-controlled hardware.",
        narration:
          "The Pixel 9 has re-associated with the rogue access point. Its traffic is now leaving the house through attacker-controlled hardware.",
      }),
      common({
        at: 10.5,
        phase: "defense",
        threat: 73,
        label: "Defense activated",
        detail: "WiFi Guard blocked the suspicious Wi-Fi network and guided devices back to the real network", severity: "good",
        note: "The rogue BSSID has been blacklisted and clients were steered back to the genuine access point.",
        narration:
          "The rogue BSSID is blacklisted and affected clients were steered back to the genuine access point with its known hardware address pinned.",
      }),
      common({
        at: 15,
        phase: "recovered",
        threat: 92,
        label: "Network stabilised",
        detail: "All devices are connected to the genuine Wi-Fi network again", severity: "good",
        note: "Every client is back on the genuine access point. Threat Confidence is recovering.",
        narration: CALM_NARRATION,
      }),
    ];
  }

  return [
    common({
      at: 0,
      phase: "recon",
      threat: 85,
      label: "Unexpected DNS responder",
      detail: "Someone is sending fake website address information to devices on your network",
      severity: "warn",
      deviceId: attackerId,
      note: "DNS answers are arriving from a host that is not the configured resolver.",
      narration:
        "DNS answers for trusted names are arriving from a host that is not your configured resolver. The replies are racing the legitimate ones.",
    }),
    common({
      at: 3,
      phase: "suspicious",
      threat: 60,
      label: "Forged DNS answer",
      detail: "A trusted website name was pointed to a suspicious local address", severity: "warn",
      deviceId: victimId,
      note: "A trusted domain resolved to a local address. Threat Confidence is decreasing.",
      narration:
        "A well-known domain just resolved to an address inside your own network. That answer did not come from the internet — it was forged locally.",
    }),
    common({
      at: 6.5,
      phase: "intercept",
      threat: 27,
      label: "Traffic redirected",
      detail: "Your browser request is being sent to a suspicious server instead of the real website", severity: "danger",
      deviceId: victimId,
      note: "Workstation requests are landing on an attacker-controlled host instead of the real service.",
      narration:
        "Requests from the Workstation are now landing on an attacker-controlled host instead of the real service — the setup for credential capture.",
    }),
    common({
      at: 10.5,
      phase: "defense",
      threat: 74,
      label: "Defense activated",
      detail: "WiFi Guard blocked the fake DNS response and restored trusted name resolution", severity: "good",
      note: "Forged answers are discarded and resolution is pinned to the trusted encrypted resolver.",
      narration:
        "Forged answers are being discarded and name resolution has been pinned to the trusted encrypted resolver, so the spoofed replies no longer win.",
    }),
    common({
      at: 15,
      phase: "recovered",
      threat: 92,
      label: "Network stabilised",
      detail: "Website addresses are resolving through the trusted DNS service again", severity: "good",
      note: "Name resolution is verified again. Threat Confidence is recovering.",
      narration: CALM_NARRATION,
    }),
  ];
}

class NetworkEngine {
  state: NetState;
  private listeners = new Set<() => void>();
  private raf = 0;
  private last = 0;
  private acc = 0;
  private packetId = 1;
  private eventId = 1;
  private noteId = 1;
  private alertId = 1;
  private attackT = -1;
  private attackStep = 0;
  private steps: Step[] = [];
  private arpAttackContext: ArpAttackContext | null = null;
  private activeAttackerId: string | null = null;
  private activeVictimId: string | null = null;
  private simulatedAttackerCreated = false;
  private running = false;
  /** deterministic during construction so SSR and the client agree */
  private seed = 20260803;
  private rnd: () => number = () => {
    this.seed = (this.seed * 1664525 + 1013904223) % 4294967296;
    return this.seed / 4294967296;
  };

  constructor() {
    const devices = seedDevices();
    this.state = {
      devices,
      packets: [],
      events: [],
      notes: [],
      alerts: [],
      history: [],
      threat: 92,
      threatTarget: 92,
      trend: "stable",
      status: "SAFE",
      phase: "calm",
      attackActive: false,
      attackType: null,
      paused: false,
      lastScan: Date.now() - 1000 * 60 * 4,
      scanning: false,
      scanProgress: 0,
      firewall: "active",
      blocked: 0,
      narration: CALM_NARRATION,
      hasScanned: false, // Track if a real scan has been performed
    };
    for (const d of devices) this.retune(d, 0);
    for (let i = 0; i < 40; i++) this.state.history.push(this.sample(i));
    this.state.events = [
      {
        id: this.eventId++,
        t: 0,
        time: "baseline",
        label: "Network baseline established",
        detail: "6 devices fingerprinted and trusted",
        severity: "info",
        phase: "calm",
      },
      {
        id: this.eventId++,
        t: 0,
        time: "baseline",
        label: "Living Room TV connected",
        detail: "DHCP lease issued for 192.168.1.42",
        severity: "info",
        deviceId: "tv",
        phase: "calm",
      },
    ];
    this.state.notes = [
      {
        id: this.noteId++,
        time: "baseline",
        text: "Baseline learned for all 6 devices. Traffic shape, latency and hardware addresses recorded.",
        tone: "info",
      },
    ];
    // live from here on
    this.rnd = Math.random;
  }

  subscribe = (fn: () => void) => {
    this.listeners.add(fn);
    if (!this.running) this.start();
    return () => {
      this.listeners.delete(fn);
    };
  };

  getSnapshot = () => this.state;

  private emit() {
    this.state = { ...this.state };
    for (const fn of this.listeners) fn();
  }

  private start() {
    if (typeof window === "undefined") return;
    this.running = true;
    this.last = performance.now();
    const loop = (now: number) => {
      const dt = Math.min(0.05, (now - this.last) / 1000);
      this.last = now;
      if (!this.state.paused) this.tick(dt);
      this.raf = requestAnimationFrame(loop);
    };
    this.raf = requestAnimationFrame(loop);
  }

  stop() {
    cancelAnimationFrame(this.raf);
    this.running = false;
  }

  private sample(i: number): Sample {
    const total = this.state.devices.reduce((a, d) => a + d.down, 0);
    return {
      t: i,
      down: total || 40 + this.rnd() * 20,
      up: total * 0.18 || 8,
      latency: 14 + this.rnd() * 6,
      loss: this.rnd() * 0.4,
    };
  }

  private retune(d: Device, dt: number) {
    const drift = (v: number, target: number, k: number) =>
      v + (target - v) * Math.min(1, k * (dt || 1));
    const base: Record<DeviceKind, number> = {
      tv: 48,
      laptop: 26,
      phone: 9,
      camera: 6,
      printer: 0.6,
      unknown: 3,
      router: 0,
    };
    if (!d.online) {
      d.down = 0;
      d.up = 0;
      d.pps = 0;
      d.connections = 0;
      d.weight = 0.08;
      return;
    }
    const b = base[d.kind] ?? 4;
    const jitter = 0.75 + this.rnd() * 0.5;
    d.down = drift(d.down, b * jitter, 0.6);
    d.up = drift(d.up, b * 0.22 * jitter, 0.6);
    d.latency = drift(d.latency, (d.hostile ? 42 : 12) + this.rnd() * 10, 0.5);
    d.loss = drift(d.loss, d.hostile ? 1.8 : this.rnd() * 0.5, 0.4);
    d.signal = drift(d.signal || 80, d.kind === "camera" ? 62 : 78 + this.rnd() * 18, 0.3);
    d.pps = Math.round(d.down * 82 + this.rnd() * 40);
    d.connections = Math.max(1, Math.round(d.down / 6) + (d.hostile ? 9 : 1));
    d.weight = Math.min(1, Math.max(0.08, d.down / 50));
  }

  private spawn(d: Device) {
    const s = this.state;
    const hostileNow = d.hostile && (s.phase === "suspicious" || s.phase === "intercept" || s.phase === "defense");
    const verdict: Verdict = hostileNow
      ? this.rnd() < 0.72
        ? "malicious"
        : "suspicious"
      : d.hostile
        ? this.rnd() < 0.5
          ? "suspicious"
          : "normal"
        : s.phase === "intercept" &&
        d.id ===
        (this.arpAttackContext?.victimId ??
          s.devices.find((device) => device.kind === "laptop")?.id) && 
        this.rnd() < 0.4
          ? "suspicious"
          : this.rnd() < 0.03
            ? "suspicious"
            : "normal";
    const protocol =
      verdict === "malicious"
        ? s.attackType === "dns"
          ? "DNS"
          : "ARP"
        : (PROTOCOLS[Math.floor(this.rnd() * (PROTOCOLS.length - 1))] ?? "TCP");
    const reason =
      verdict === "malicious"
        ? s.attackType === "dns"
          ? "Forged DNS answer from a host that is not the configured resolver"
          : "Unsolicited ARP reply claiming the gateway address"
        : verdict === "suspicious"
          ? "Traffic pattern deviates from this device's learned baseline"
          : "Matches the learned baseline for this device";
    const blocked = verdict === "malicious" && s.firewall === "engaged";
    s.packets.push({
      id: this.packetId++,
      deviceId: d.id,
      dir: this.rnd() < (d.kind === "tv" ? 0.85 : 0.6) ? "down" : "up",
      progress: 0,
      speed: 0.28 + this.rnd() * 0.35,
      verdict,
      protocol,
      size: 64 + Math.floor(this.rnd() * 1400),
      reason,
      blocked,
      blockAt: blocked ? 0.3 + this.rnd() * 0.25 : 2,
    });
  }

  private syncBackendThreats = async () => {
    try {
      const response = await fetch("https://wifi-guard-production.up.railway.app/threat-events?limit=10");

      if (!response.ok) return;

      const data = await response.json();

      const backendEvents: NetEvent[] = (data.events ?? []).map(
        (event: any, index: number) => ({
          id: 100000 + index,
          t: Date.now(),
          time: event.timestamp
            ? new Date(event.timestamp).toLocaleTimeString("en-GB", {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })
            : fmtTime(),
          label: event.threat_type === "suspicious_website"
            ? "Suspicious website detected"
            : event.threat_type ?? "Threat detected",
          detail: event.reason ?? "A network threat was detected.",
          severity:
            event.severity === "danger"
              ? "danger"
              : event.severity === "warn"
                ? "warn"
                : "info",
          deviceId: event.source_ip
            ? this.state.devices.find((d) => d.ip === event.source_ip)?.id
            : undefined,
          phase: "intercept",
        }),
      );

      const simulatedEvents = this.state.events.filter(
        (event) => event.id < 100000,
      );

      this.state.events = [...simulatedEvents, ...backendEvents].slice(-60);

      const hasDanger = backendEvents.some((e) => e.severity === "danger");
      const hasWarning = backendEvents.some((e) => e.severity === "warn");

      if (hasDanger) {
        this.state.threatTarget = 25;
      } else if (hasWarning) {
        this.state.threatTarget = 40;
      } else {
        this.state.threatTarget = 92;
      }
    } catch {
      // Backend may be unavailable; keep existing events.
    }
  };

  private pushEvent(
    label: string,
    detail: string,
    severity: NetEvent["severity"],
    deviceId?: string,
    phase: Phase = this.state.phase,
  ) {
    this.state.events = [
      ...this.state.events,
      { id: this.eventId++, t: Date.now(), time: fmtTime(), label, detail, severity, deviceId, phase },
    ].slice(-60);
  }

  private pushNote(text: string, tone: AiNote["tone"]) {
    this.state.notes = [
      ...this.state.notes,
      { id: this.noteId++, time: fmtTime(), text, tone },
    ].slice(-14);
  }

  private setStatus() {
    const t = this.state.threat;
    this.state.status = t > 80 ? "SAFE" : t > 45 ? "WARNING" : "HIGH RISK";
  }

  private tick(dt: number) {
    const s = this.state;

    // move packets, dropping the ones defense rejected mid-flight
    const alive: Packet[] = [];
    for (const p of s.packets) {
      p.progress += p.speed * dt;
      if (p.blocked && p.progress >= p.blockAt) {
        s.blocked += 1;
        continue;
      }
      if (p.progress < 1) alive.push(p);
    }
    s.packets = alive;

    // spawn
    for (const d of s.devices) {
      if (!d.online) continue;
      const rate = 0.7 + d.weight * 6 + (d.hostile ? 7 : 0);
      if (this.rnd() < rate * dt && s.packets.length < 90) this.spawn(d);
    }

    // threat confidence eases toward its target so it always feels alive
    const diff = s.threatTarget - s.threat;
    if (Math.abs(diff) > 0.15) {
      s.threat += diff * Math.min(1, dt * 1.8);
      s.trend = diff < 0 ? "falling" : "recovering";
    } else {
      s.threat = s.threatTarget;
      s.trend = "stable";
    }
    this.setStatus();

    if (s.scanning) {
      s.scanProgress = Math.min(1, s.scanProgress + dt / 2.4);
      if (s.scanProgress >= 1) this.finishScan();
    }

    this.acc += dt;
    if (this.acc > 0.5) {
      this.acc = 0;
      for (const d of s.devices) this.retune(d, 1);
      s.history = [...s.history.slice(-59), this.sample((s.history.at(-1)?.t ?? 0) + 1)];
      if (!s.attackActive && s.threatTarget < 92) s.threatTarget = 92;
    }

    if (s.attackActive) this.attackTick(dt);
    if (this.acc === 0) {
      void this.syncBackendThreats();
    }
    this.emit();
  }

  private attackTick(dt: number) {
    this.attackT += dt;

    const s = this.state;

    const attackerId =
      this.arpAttackContext?.attackerId ??
      this.activeAttackerId ??
      "unknown";

    const attacker = s.devices.find((d) => d.id === attackerId);

    while (this.attackStep < this.steps.length) {
      const step = this.steps[this.attackStep];

      if (!step || this.attackT < step.at) break;

      s.phase = step.phase;
      s.threatTarget = step.threat;
      s.threat = step.threat;
      s.narration = step.narration;

      this.pushEvent(
        step.label,
        step.detail,
        step.severity,
        step.deviceId,
        step.phase,
      );

      this.pushNote(step.note, step.severity);

      if (step.phase === "recon" && attacker) {
        attacker.hostile = true;
      }

      if (step.phase === "intercept") {
        const victim = s.devices.find(
          (d) => d.id === step.deviceId,
        );

        if (victim) {
          victim.threats += 1;
        }

        if (attacker) {
          attacker.threats += 1;
        }
      }

      if (step.phase === "defense") {
        s.firewall = "engaged";

        for (const p of s.packets) {
          if (p.verdict === "malicious") {
            p.blocked = true;
            p.blockAt = Math.min(1, p.progress + 0.06);
          }
        }
      }

      if (step.phase === "recovered") {
        if (attacker) {
          attacker.hostile = false;
        }

        s.attackActive = false;
        s.attackType = null;
        s.firewall = "active";

        this.attackT = -1;
        this.attackStep = 0;
        this.steps = [];

        // Remove only the temporary ARP simulation device.
        if (this.simulatedAttackerCreated) {
          s.devices = s.devices.filter(
            (d) => d.id !== this.arpAttackContext?.attackerId,
          );

          this.simulatedAttackerCreated = false;
        }

        this.arpAttackContext = null;

        setTimeout(() => {
          if (!this.state.attackActive) {
            this.state.phase = "calm";
            this.emit();
          }
        }, 6000);

        break;
      }

      this.attackStep++;
    }
  }

  private finishScan() {
    const s = this.state;
    s.scanning = false;
    s.scanProgress = 0;
    s.lastScan = Date.now();
    this.pushEvent(
      "Active scan complete",
      `${s.devices.filter((d) => d.online).length} hosts answered, ${s.devices.filter((d) => !d.trusted).length} unrecognised`,
      "info",
    );
    const rogue = s.devices.find((d) => !d.trusted && d.online && !d.blockedByUser);
    if (rogue && !s.alerts.some((a) => a.deviceId === rogue.id)) {
      s.alerts = [
        ...s.alerts,
        {
          id: this.alertId++,
          title: "Unknown device joined",
          detail: `${rogue.ip} · ${rogue.vendor}`,
          deviceId: rogue.id,
          time: fmtTime(),
        },
      ];
      this.pushNote(
        `A host at ${rogue.ip} cannot be matched to any known vendor fingerprint. Review it before trusting it.`,
        "warn",
      );
    }
    this.emit();
  }
  private getAttackDevices() {
    const s = this.state;

    const victim =
      s.devices.find((d) => d.kind === "laptop" && d.online) ??
      s.devices.find((d) => d.kind !== "router" && d.online);

    const gateway = s.devices.find(
      (d) => d.kind === "router" && d.online,
    );

    const attacker =
      s.devices.find((d) => d.kind === "unknown" && d.online) ?? {
        id: "simulated-rogue",
        name: "Simulated Rogue Host",
        kind: "unknown" as DeviceKind,
        ip: "SIMULATED",
        mac: "SIMULATED",
        vendor: "Attack Lab",
        online: true,
        trusted: false,
        angle: Math.PI / 2,
      };

    return { victim, gateway, attacker };
  }
  // ---- actions ----
  triggerAttack = (type: AttackType = "arp") => {
    if (this.state.attackActive) return;

    const s = this.state;

    this.arpAttackContext = null;
    this.simulatedAttackerCreated = false;

    const { victim: attackVictim, attacker: attackAttacker } =
      this.getAttackDevices();

    this.activeAttackerId = attackAttacker?.id ?? null;
    this.activeVictimId = attackVictim?.id ?? null;
    if (type === "arp") {
      const victim =
        s.devices.find((d) => d.kind === "laptop" && d.online) ??
        s.devices.find((d) => d.kind !== "router" && d.online);

      const gateway =
        s.devices.find((d) => d.kind === "router" && d.online);

      if (victim && gateway) {
        const attackerId = "simulated-rogue";

        const attacker: Device = {
          id: attackerId,
          name: "Simulated Rogue Host",
          kind: "unknown",
          ip: "SIMULATED",
          mac: "SIMULATED",
          vendor: "Attack Lab",
          angle: Math.PI / 2,
          weight: 0.35,
          down: 0,
          up: 0,
          latency: 0,
          loss: 0,
          signal: 0,
          pps: 0,
          connections: 0,
          threats: 0,
          hostile: false,
          online: true,
          trusted: false,
          blockedByUser: false,
        };

        s.devices = [...s.devices, attacker];

        this.arpAttackContext = {
          victimId: victim.id,
          victimName: victim.name,
          victimIp: victim.ip,
          gatewayIp: gateway.ip,
          attackerId,
          attackerIp: attacker.ip,
        };

        this.simulatedAttackerCreated = true;
      }
    }
    if (type !== "arp" && attackAttacker?.id === "simulated-rogue") {
      const attacker: Device = {
        id: "simulated-rogue",
        name: "Simulated Rogue Host",
        kind: "unknown",
        ip: "SIMULATED",
        mac: "SIMULATED",
        vendor: "Attack Lab",
        angle: Math.PI / 2,
        weight: 0.35,
        down: 0,
        up: 0,
        latency: 0,
        loss: 0,
        signal: 0,
        pps: 0,
        connections: 0,
        threats: 0,
        hostile: false,
        online: true,
        trusted: false,
        blockedByUser: false,
      };

      s.devices = [...s.devices, attacker];
      this.simulatedAttackerCreated = true;
    }
    s.attackActive = true;
    s.attackType = type;
    s.blocked = 0;

    this.steps = script(
      type,
      this.arpAttackContext ?? undefined,
      attackVictim?.id,
      attackAttacker?.id,
    );

    this.attackT = 0;
    this.attackStep = 0;

    this.emit();
  };

  togglePause = () => {
    this.state.paused = !this.state.paused;
    this.emit();
  };

  runScan = async () => {
    if (this.state.scanning) return;
    this.state.scanning = true;
    this.state.scanProgress = 0;
    this.emit();

    try {
      // Call the real Flask API to scan the network
      const response = await scanNetwork();

      if (response.success && response.devices.length > 0) {
        // Convert API devices to frontend device format
        const newDevices = response.devices.map((apiDevice: ApiDevice, index: number) => {
          // Map device_type to DeviceKind
          let kind: DeviceKind = "unknown";
          const deviceType = apiDevice.device_type?.trim().toLowerCase();

          if (deviceType?.includes("router") || deviceType?.includes("gateway")) {
            kind = "router";
          }
          else if (deviceType === "laptop/pc") kind = "laptop";
          else if (deviceType === "phone") kind = "phone";
          else if (deviceType === "iot") kind = "tv";
          // Generate a simple ID from IP address
          // Keep the real gateway mapped to the central router node.
          const id =
            deviceType?.includes("router") || deviceType?.includes("gateway")
              ? "router"
              : apiDevice.ip.replace(/\./g, "-");

          // Use hostname if available, otherwise use IP
          const name = apiDevice.hostname !== "Unknown" ? apiDevice.hostname : `Device ${apiDevice.ip}`;

          return {
            id,
            name,
            kind,
            ip: apiDevice.ip,
            mac: apiDevice.mac,
            vendor: apiDevice.vendor,
            angle: (index / response.devices.length) * Math.PI * 2 - Math.PI / 2,
            weight: 0.4,
            down: 0,
            up: 0,
            latency: 0,
            loss: 0,
            signal: 0,
            pps: 0,
            connections: 0,
            threats: 0,
            hostile: false,
            online: true,
            trusted: true,
            blockedByUser: false,
          } as Device;
        });

        // Replace mock devices with real scanned devices
        this.state.devices = newDevices;
        this.state.hasScanned = true; // Mark that a real scan has been performed
        this.state.alerts = [];
        this.state.notes = [];

        // Re-tune all devices
        for (const d of this.state.devices) this.retune(d, 0);

        // Complete the scan
        this.finishScan();
      } else {
        // If no devices found, still complete the scan
        this.finishScan();
      }
    } catch (error) {
      console.error("Failed to scan network:", error);
      this.pushNote("Network scan failed. Using fallback mock data.", "warn");
      // Complete the scan even on error
      this.finishScan();
    }
  };

  resolveAlert = (id: number, action: "review" | "ignore" | "block") => {
    const s = this.state;
    const alert = s.alerts.find((a) => a.id === id);
    s.alerts = s.alerts.filter((a) => a.id !== id);
    if (alert && action === "block") {
      const d = s.devices.find((x) => x.id === alert.deviceId);
      if (d) {
        d.blockedByUser = true;
        d.online = false;
        d.hostile = false;
        s.packets = s.packets.filter((p) => p.deviceId !== d.id);
        this.pushEvent("Device blocked", `${d.name} (${d.ip}) removed from the network`, "good", d.id);
        this.pushNote(`${d.name} has been blocked. It can no longer send or receive on this network.`, "good");
      }
    }
    if (alert && action === "ignore") {
      const d = s.devices.find((x) => x.id === alert.deviceId);
      if (d) d.trusted = true;
      this.pushNote(`${alert.detail} was marked as trusted by you. It will not be flagged again.`, "info");
    }
    this.emit();
  };

  allowDevice = (id: string) => {
    const d = this.state.devices.find((x) => x.id === id);
    if (!d) return;
    d.blockedByUser = false;
    d.online = true;
    this.pushEvent("Device readmitted", `${d.name} (${d.ip}) allowed back on the network`, "info", d.id);
    this.emit();
  };
}

let engine: NetworkEngine | null = null;
function getEngine() {
  if (!engine) engine = new NetworkEngine();
  return engine;
}

interface Ctx {
  state: NetState;
  triggerAttack: (type?: AttackType) => void;
  togglePause: () => void;
  runScan: () => void;
  resolveAlert: (id: number, action: "review" | "ignore" | "block") => void;
  allowDevice: (id: string) => void;
}

const NetworkContext = createContext<Ctx | null>(null);

export function NetworkProvider({ children }: { children: ReactNode }) {
  const eng = useMemo(getEngine, []);
  const [state, setState] = useState(eng.getSnapshot());
  const frame = useRef(0);

  useEffect(() => {
    return eng.subscribe(() => {
      // throttle React updates to ~30fps
      const now = performance.now();
      if (now - frame.current < 33) return;
      frame.current = now;
      setState(eng.getSnapshot());
    });
  }, [eng]);

  const value = useMemo<Ctx>(
    () => ({
      state,
      triggerAttack: eng.triggerAttack,
      togglePause: eng.togglePause,
      runScan: eng.runScan,
      resolveAlert: eng.resolveAlert,
      allowDevice: eng.allowDevice,
    }),
    [state, eng],
  );

  return <NetworkContext.Provider value={value}>{children}</NetworkContext.Provider>;
}

export function useNetwork() {
  const ctx = useContext(NetworkContext);
  if (!ctx) throw new Error("useNetwork must be used inside NetworkProvider");
  return ctx;
}

export const ROUTER_INFO = {
  id: "router",
  name: "Main Gateway",
  ip: "",
  mac: "",
  vendor: "",
  ssid: "",
};

export function verdictToken(v: Verdict) {
  return v === "malicious" ? "danger" : v === "suspicious" ? "warn" : "safe";
}

export function deviceStatus(d: Device): DeviceStatus {
  if (d.hostile || d.threats > 0) return "threatened";
  if (d.down > 20) return "busy";
  return "normal";
}
