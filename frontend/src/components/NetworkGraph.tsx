import { useMemo } from "react";
import { useNetwork, ROUTER_INFO, deviceStatus, type Device, type Packet } from "@/lib/network-sim";
import { cn } from "@/lib/utils";

const W = 820;
const H = 560;
const CX = W / 2;
const CY = H / 2;

export interface NodePos {
  id: string;
  x: number;
  y: number;
}

export function useLayout(): Record<string, NodePos> {
  const { state } = useNetwork();

  return useMemo(() => {
    const map: Record<string, NodePos> = {
      router: { id: "router", x: CX, y: CY },
    };

    const laptop = state.devices.find((d) => d.kind === "laptop");

    for (const d of state.devices) {
      // The real scanned gateway occupies the central router position.
      if (d.kind === "router") {
        map[d.id] = { id: d.id, x: CX, y: CY };
        continue;
      }

      let angle = d.angle;
      let radius = 235 - d.weight * 70;

      if (d.id === "simulated-rogue") {
        angle = 0;
        radius = 285;
      } else if (d.hostile && laptop) {
        angle = laptop.angle + 0.34;
        radius = 150;
      }

      map[d.id] = {
        id: d.id,
        x: CX + Math.cos(angle) * radius * 1.28,
        y: CY + Math.sin(angle) * radius,
      };
    }

    return map;
  }, [state.devices]);
}

function packetPoint(p: Packet, pos: NodePos) {
  const t = p.dir === "up" ? p.progress : 1 - p.progress;
  return { x: pos.x + (CX - pos.x) * t, y: pos.y + (CY - pos.y) * t };
}

const ICONS: Record<string, string> = {
  laptop: "M4 5h16v10H4zM2 17h20l-1 2H3z",
  phone: "M8 3h8v18H8z",
  tv: "M3 5h18v11H3zM8 20h8",
  printer: "M6 9V4h12v5M6 18h12v3H6zM4 9h16v7H4z",
  camera: "M4 7h11l2 3h3v8H4z",
  unknown: "M12 3a9 9 0 100 18 9 9 0 000-18zM12 8v5M12 17v.5",
};

function verdictClass(v: Packet["verdict"]) {
  return v === "malicious"
    ? "fill-danger stroke-danger"
    : v === "suspicious"
      ? "fill-warn stroke-warn"
      : "fill-safe stroke-safe";
}

export function NetworkGraph({
  selected,
  onSelect,
  onPacket,
}: {
  selected: string | null;
  onSelect: (id: string | null) => void;
  onPacket: (p: Packet, device: Device) => void;
}) {
  const { state } = useNetwork();
  const layout = useLayout();
  const focus = selected ? layout[selected] : null;
  const scale = focus ? 1.55 : 1;
  const tx = focus ? CX - focus.x * scale : 0;
  const ty = focus ? CY - focus.y * scale : 0;

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="h-full w-full select-none"
      onClick={() => onSelect(null)}
      role="img"
      aria-label="Live map of the WiFi network"
    >
      <defs>
        <radialGradient id="wg-core" cx="50%" cy="50%">
          <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.35" />
          <stop offset="100%" stopColor="var(--primary)" stopOpacity="0" />
        </radialGradient>
        <pattern id="wg-grid" width="40" height="40" patternUnits="userSpaceOnUse">
          <path d="M40 0H0V40" fill="none" stroke="var(--grid)" strokeWidth="1" />
        </pattern>
      </defs>

      <rect width={W} height={H} fill="url(#wg-grid)" opacity="0.5" />

      <g
        style={{
          transform: `translate(${tx}px, ${ty}px) scale(${scale})`,
          transition: "transform 700ms cubic-bezier(0.22,1,0.36,1)",
        }}
      >
        <circle cx={CX} cy={CY} r={210} fill="url(#wg-core)" />

        {/* radar sweep while an active scan is running */}
        {state.scanning && (
          <>
            <circle
              cx={CX}
              cy={CY}
              r={30 + state.scanProgress * 250}
              fill="none"
              stroke="var(--primary)"
              strokeWidth={2}
              opacity={0.85 * (1 - state.scanProgress)}
            />
            <line
              x1={CX}
              y1={CY}
              x2={CX + Math.cos(state.scanProgress * Math.PI * 4) * 280}
              y2={CY + Math.sin(state.scanProgress * Math.PI * 4) * 280}
              stroke="var(--primary)"
              strokeWidth={1.5}
              opacity={0.4}
            />
          </>
        )}

        {/* links */}
        {state.devices.map((d) => {
          if (d.kind === "router") return null;

          const pos = layout[d.id];
          if (!pos) return null;
          const dim = selected && selected !== d.id && selected !== "router";
          return (
            <line
              key={`l-${d.id}`}
              x1={pos.x}
              y1={pos.y}
              x2={CX}
              y2={CY}
              stroke={d.hostile ? "var(--danger)" : "var(--border)"}
              strokeWidth={d.hostile ? 3 : 1 + d.weight * 3}
              opacity={dim ? 0.15 : d.hostile ? 0.95 : 0.5}
              style={{ transition: "opacity 400ms, stroke-width 600ms" }}
            />
          );
        })}

        {/* attacker → victim interception path */}
        {state.devices.some((d) => d.hostile) &&
          (() => {
            const att = layout["simulated-rogue"] ?? layout["unknown"];
            const vic = layout["laptop"];
            if (!att || !vic) return null;
            return (
              <line
                x1={att.x}
                y1={att.y}
                x2={vic.x}
                y2={vic.y}
                stroke="var(--danger)"
                strokeWidth={2}
                strokeDasharray="6 6"
                opacity={0.8}
                className="wg-blip"
              />
            );
          })()}

        {/* packets */}
        {state.packets.map((p) => {
          const pos = layout[p.deviceId];
          const device = state.devices.find((d) => d.id === p.deviceId);
          if (!pos || !device) return null;
          if (selected && selected !== "router" && selected !== p.deviceId) return null;
          const pt = packetPoint(p, pos);
          // a rejected frame fades and shrinks where defense stopped it
          const dying = p.blocked ? Math.max(0, 1 - (p.progress - p.blockAt + 0.12) / 0.12) : 1;
          return (
            <g key={p.id} opacity={p.blocked ? Math.min(1, dying) : 1}>
              {p.blocked && (
                <circle
                  cx={pt.x}
                  cy={pt.y}
                  r={9}
                  fill="none"
                  stroke="var(--safe)"
                  strokeWidth={1.2}
                  opacity={0.8}
                />
              )}
              <circle
                cx={pt.x}
                cy={pt.y}
                r={p.verdict === "normal" ? 3 : 4.5}
                className={cn(verdictClass(p.verdict), "cursor-pointer")}
                strokeWidth={p.verdict === "normal" ? 0 : 6}
                strokeOpacity={0.18}
                onClick={(e) => {
                  e.stopPropagation();
                  onPacket(p, device);
                }}
              />
            </g>
          );
        })}


        {/* router */}
        <g
          className="cursor-pointer"
          onClick={(e) => {
            e.stopPropagation();
            onSelect("router");
          }}
          opacity={selected && selected !== "router" ? 0.45 : 1}
          style={{ transition: "opacity 400ms" }}
        >
          {state.status !== "SAFE" && (
            <circle cx={CX} cy={CY} r={38} fill="none" stroke="var(--danger)" className="wg-pulse-ring" />
          )}
          <circle
            cx={CX}
            cy={CY}
            r={34}
            fill="var(--card)"
            stroke={state.status === "SAFE" ? "var(--primary)" : "var(--danger)"}
            strokeWidth={2}
          />
          <path
            d="M-14 4a20 20 0 0128 0M-8 10a12 12 0 0116 0M0 16.5v.01"
            transform={`translate(${CX} ${CY - 6})`}
            fill="none"
            stroke={state.status === "SAFE" ? "var(--primary)" : "var(--danger)"}
            strokeWidth={2.2}
            strokeLinecap="round"
          />
          <text
            x={CX}
            y={CY + 54}
            textAnchor="middle"
            className="fill-muted-foreground font-mono"
            fontSize={11}
          >
            {state.devices.find((d) => d.kind === "router")?.ip ?? ROUTER_INFO.ip}
          </text>
        </g>

        {/* devices */}
        {state.devices.map((d) => {
          if (d.kind === "router") return null;

          const pos = layout[d.id];
          if (!pos) return null;
          const dim = selected && selected !== d.id;
          const r = 20 + d.weight * 10;
          return (
            <g
              key={d.id}
              className="cursor-pointer"
              opacity={dim ? 0.35 : 1}
              onClick={(e) => {
                e.stopPropagation();
                onSelect(d.id);
              }}
              style={{
                transform: `translate(${pos.x}px, ${pos.y}px)`,
                transition: "transform 900ms cubic-bezier(0.22,1,0.36,1), opacity 400ms",
              }}
            >
              {d.hostile && (
                <circle r={r + 6} fill="none" stroke="var(--danger)" className="wg-pulse-ring" />
              )}
              <circle
                r={r}
                fill="var(--card)"
                stroke={d.hostile ? "var(--danger)" : selected === d.id ? "var(--primary)" : "var(--border)"}
                strokeWidth={2}
              />
              <path
                d={ICONS[d.kind] ?? ICONS["unknown"]}
                transform="translate(-12 -12)"
                fill="none"
                stroke={d.hostile ? "var(--danger)" : "var(--foreground)"}
                strokeWidth={1.6}
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              {/* live status dot */}
              <circle
                cx={r * 0.72}
                cy={-r * 0.72}
                r={4}
                className={
                  deviceStatus(d) === "threatened"
                    ? "fill-danger wg-blip"
                    : deviceStatus(d) === "busy"
                      ? "fill-warn"
                      : "fill-safe"
                }
                stroke="var(--card)"
                strokeWidth={1.5}
                opacity={d.online ? 1 : 0.3}
              />
              <text
                y={r + 16}
                textAnchor="middle"
                className="fill-foreground font-mono"
                fontSize={11}
              >
                {d.name}
              </text>
              <text
                y={r + 29}
                textAnchor="middle"
                className="fill-muted-foreground font-mono"
                fontSize={9.5}
              >
                {d.down.toFixed(1)} Mbps
              </text>
            </g>
          );
        })}
      </g>
    </svg>
  );
}
