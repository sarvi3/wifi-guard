import { useNetwork } from "@/lib/network-sim";
import { cn } from "@/lib/utils";

const W = 300;
const H = 190;
const CX = W / 2;
const CY = H / 2;
const RX = 118;
const RY = 66;

/**
 * A calm, non-interactive preview of the live map for the dashboard.
 */
export function MiniMap({ className }: { className?: string }) {
  const { state } = useNetwork();
  const pos = (angle: number) => ({ x: CX + Math.cos(angle) * RX, y: CY + Math.sin(angle) * RY });

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className={cn("h-full w-full", className)}
      role="img"
      aria-label="Preview of the live network map"
    >
      <defs>
        <radialGradient id="wg-mini-core" cx="50%" cy="50%">
          <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.28" />
          <stop offset="100%" stopColor="var(--primary)" stopOpacity="0" />
        </radialGradient>
      </defs>
      <circle cx={CX} cy={CY} r={96} fill="url(#wg-mini-core)" />

      {state.scanning && (
        <circle
          cx={CX}
          cy={CY}
          r={20 + state.scanProgress * 110}
          fill="none"
          stroke="var(--primary)"
          strokeWidth={1.5}
          opacity={1 - state.scanProgress}
        />
      )}

      {state.devices.map((d) => {
        const p = pos(d.angle);
        return (
          <line
            key={`ml-${d.id}`}
            x1={p.x}
            y1={p.y}
            x2={CX}
            y2={CY}
            stroke={d.hostile ? "var(--danger)" : "var(--border)"}
            strokeWidth={d.hostile ? 1.8 : 1}
            opacity={d.online ? (d.hostile ? 0.9 : 0.45) : 0.15}
          />
        );
      })}

      {state.packets.slice(0, 34).map((p) => {
        const d = state.devices.find((x) => x.id === p.deviceId);
        if (!d) return null;
        const base = pos(d.angle);
        const t = p.dir === "up" ? p.progress : 1 - p.progress;
        const x = base.x + (CX - base.x) * t;
        const y = base.y + (CY - base.y) * t;
        return (
          <circle
            key={p.id}
            cx={x}
            cy={y}
            r={p.verdict === "normal" ? 1.6 : 2.4}
            className={
              p.verdict === "malicious"
                ? "fill-danger"
                : p.verdict === "suspicious"
                  ? "fill-warn"
                  : "fill-safe"
            }
            opacity={p.blocked ? 0.5 : 1}
          />
        );
      })}

      {state.devices.map((d) => {
        const p = pos(d.angle);
        return (
          <circle
            key={`md-${d.id}`}
            cx={p.x}
            cy={p.y}
            r={d.hostile ? 6 : 5}
            fill="var(--card)"
            stroke={d.hostile ? "var(--danger)" : d.online ? "var(--primary)" : "var(--border)"}
            strokeWidth={1.6}
            opacity={d.online ? 1 : 0.4}
          />
        );
      })}

      <circle
        cx={CX}
        cy={CY}
        r={13}
        fill="var(--card)"
        stroke={state.status === "SAFE" ? "var(--primary)" : "var(--danger)"}
        strokeWidth={2}
      />
      <path
        d="M-7 2a10 10 0 0114 0M-4 5.5a6 6 0 018 0M0 9v.01"
        transform={`translate(${CX} ${CY - 3})`}
        fill="none"
        stroke={state.status === "SAFE" ? "var(--primary)" : "var(--danger)"}
        strokeWidth={1.6}
        strokeLinecap="round"
      />
    </svg>
  );
}
