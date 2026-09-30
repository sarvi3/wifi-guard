import {
  Activity,AlertTriangle,
  Beaker,CheckCircle2,
  Laptop,Play,Radio,Router,
  Server,ShieldCheck,
  Smartphone,Square,Target,Wifi,XCircle,Zap,
} from "lucide-react";
import { ATTACKS, type AttackType } from "@/lib/network-sim";
import { cn } from "@/lib/utils";
import { useEffect, useMemo, useState } from "react";

type SimulationStep = {
  title: string;
  event: string;
  explanation: string;
  packet: string;
  defender: string;
};

type AttackScenario = {
  target: string;
  attacker: string;
  attackerIp: string;
  targetIp: string;
  steps: SimulationStep[];
};

const STEP_DURATION = 4500;

const SCENARIOS: Record<AttackType, AttackScenario> = {
  arp: {
    target: "Workstation",
    attacker: "Rogue Host",
    attackerIp: "192.168.1.99",
    targetIp: "192.168.1.20",
    steps: [
      {
        title: "Reconnaissance",
        event: "Network relationship observed",
        explanation:
          "The simulated attacker observes the gateway and workstation relationship before attempting to impersonate the gateway.",
        packet: "ARP observation",
        defender: "Monitoring network relationships",
      },
      {
        title: "Gateway impersonation",
        event: "Forged gateway claim",
        explanation:
          "The rogue host claims that its address belongs to the gateway. This is simulated only; no real ARP packets are sent.",
        packet: "Forged ARP reply",
        defender: "Checking gateway identity",
      },
      {
        title: "Traffic redirection",
        event: "Gateway mapping changed",
        explanation:
          "The simulated workstation now believes the rogue host is the gateway, so its traffic is redirected toward the rogue host.",
        packet: "Traffic redirected",
        defender: "Watching gateway mapping",
      },
      {
        title: "Threat detected",
        event: "Abnormal gateway mapping detected",
        explanation:
          "WiFi Guard detects that the gateway relationship has changed unexpectedly and marks the simulated mapping as suspicious.",
        packet: "Suspicious mapping",
        defender: "Threat identified",
      },
      {
        title: "Attack contained",
        event: "Trusted gateway restored",
        explanation:
          "The forged gateway mapping is rejected and the workstation returns to the trusted gateway relationship.",
        packet: "Mapping restored",
        defender: "Simulation contained",
      },
    ],
  },

  mitm: {
    target: "Workstation",
    attacker: "Interceptor",
    attackerIp: "192.168.1.88",
    targetIp: "192.168.1.20",
    steps: [
      {
        title: "Connection observed",
        event: "Target connection identified",
        explanation:
          "The simulated attacker observes the direct communication between the gateway and workstation.",
        packet: "Connection observed",
        defender: "Monitoring connection path",
      },
      {
        title: "Attacker inserted",
        event: "Interceptor placed in path",
        explanation:
          "The interceptor is positioned directly between the gateway and workstation in the simulation.",
        packet: "Path modified",
        defender: "Checking route integrity",
      },
      {
        title: "Traffic intercepted",
        event: "Packets pass through interceptor",
        explanation:
          "Packets now travel through the simulated interceptor before reaching the workstation, demonstrating the core MITM concept.",
        packet: "Packet intercepted",
        defender: "Inspecting traffic path",
      },
      {
        title: "Interception detected",
        event: "Unexpected intermediary detected",
        explanation:
          "WiFi Guard identifies an unexpected intermediary in the communication path and flags the connection.",
        packet: "Suspicious relay",
        defender: "Threat identified",
      },
      {
        title: "Connection restored",
        event: "Direct path restored",
        explanation:
          "The simulated interceptor is removed and the workstation returns to its direct gateway connection.",
        packet: "Direct connection",
        defender: "Connection protected",
      },
    ],
  },

  eviltwin: {
    target: "Mobile Device",
    attacker: "Rogue Access Point",
    attackerIp: "AP-ROGUE-01",
    targetIp: "192.168.1.30",
    steps: [
      {
        title: "Rogue AP appears",
        event: "Suspicious access point detected",
        explanation:
          "A simulated access point appears near the mobile device using a network identity designed to look familiar.",
        packet: "Beacon detected",
        defender: "Scanning nearby APs",
      },
      {
        title: "Device discovers AP",
        event: "Target sees suspicious network",
        explanation:
          "The mobile device discovers the simulated rogue access point as a possible Wi-Fi network.",
        packet: "SSID discovered",
        defender: "Comparing AP identity",
      },
      {
        title: "Association attempt",
        event: "Device attempts connection",
        explanation:
          "The mobile device attempts to associate with the rogue access point. No real Wi-Fi connection is made.",
        packet: "Association request",
        defender: "Validating access point",
      },
      {
        title: "Rogue AP detected",
        event: "Access point identity rejected",
        explanation:
          "WiFi Guard identifies that the simulated access point does not match the trusted network identity.",
        packet: "Identity mismatch",
        defender: "Threat identified",
      },
      {
        title: "Association blocked",
        event: "Connection prevented",
        explanation:
          "The simulated association is blocked and the mobile device remains connected to the trusted network.",
        packet: "Association blocked",
        defender: "Simulation contained",
      },
    ],
  },

  dns: {
    target: "Workstation",
    attacker: "DNS Injector",
    attackerIp: "192.168.1.77",
    targetIp: "192.168.1.20",
    steps: [
      {
        title: "DNS request",
        event: "Domain lookup started",
        explanation:
          "The workstation sends a simulated DNS request asking the trusted resolver for the address of a domain.",
        packet: "DNS request",
        defender: "Monitoring DNS traffic",
      },
      {
        title: "Forged response",
        event: "Fake DNS answer introduced",
        explanation:
          "The simulated attacker produces a forged DNS response containing an unexpected destination.",
        packet: "Forged DNS response",
        defender: "Validating DNS response",
      },
      {
        title: "Response inspected",
        event: "DNS answer compared",
        explanation:
          "WiFi Guard compares the simulated response with the expected DNS behaviour.",
        packet: "Response mismatch",
        defender: "Checking DNS integrity",
      },
      {
        title: "Spoof detected",
        event: "Forged DNS response detected",
        explanation:
          "The defender identifies that the simulated DNS response is suspicious and should not be trusted.",
        packet: "Spoof detected",
        defender: "Threat identified",
      },
      {
        title: "Response rejected",
        event: "Trusted lookup restored",
        explanation:
          "The forged response is rejected and the workstation returns to the trusted DNS resolver.",
        packet: "Response blocked",
        defender: "Simulation contained",
      },
    ],
  },
};

const DEVICES = {
  router: {
    name: "Gateway Router",
    ip: "192.168.1.1",
    x: 50,
    y: 23,
  },

  workstation: {
    name: "Workstation",
    ip: "192.168.1.20",
    x: 22,
    y: 72,
  },

  mobile: {
    name: "Mobile Device",
    ip: "192.168.1.30",
    x: 78,
    y: 72,
  },

  dns: {
    name: "DNS Resolver",
    ip: "8.8.8.8",
    x: 78,
    y: 34,
  },
};

export function AttackLab() {
  const [choice, setChoice] = useState<AttackType>("arp");
  const [activeAttack, setActiveAttack] = useState<AttackType | null>(null);
  const [stepIndex, setStepIndex] = useState(-1);
  const [running, setRunning] = useState(false);

  const selectedAttack = activeAttack ?? choice;
  const scenario = SCENARIOS[selectedAttack];

  const currentStep =
    stepIndex >= 0
      ? scenario.steps[Math.min(stepIndex, scenario.steps.length - 1)]
      : null;

  const detected = stepIndex >= 3;
  const contained = stepIndex >= 4;

  const progress =
    stepIndex < 0
      ? 0
      : Math.round(((stepIndex + 1) / scenario.steps.length) * 100);

  useEffect(() => {
    if (!running) return;

    const timer = window.setInterval(() => {
      setStepIndex((current) => {
        if (current >= scenario.steps.length - 1) {
          window.clearInterval(timer);
          setRunning(false);
          return current;
        }

        return current + 1;
      });
    }, STEP_DURATION);

    return () => window.clearInterval(timer);
  }, [running, scenario.steps.length]);

  const startSimulation = () => {
    setActiveAttack(choice);
    setStepIndex(0);
    setRunning(true);
  };

  const resetSimulation = () => {
    setRunning(false);
    setStepIndex(-1);
    setActiveAttack(null);
  };

  const timeline = useMemo(
    () =>
      scenario.steps.map((step, index) => ({
        ...step,
        current: index === stepIndex,
        complete: index < stepIndex,
      })),
    [scenario.steps, stepIndex],
  );

  const targetIsMobile = scenario.target === "Mobile Device";

  const target = targetIsMobile
    ? DEVICES.mobile
    : DEVICES.workstation;

  /*
   * Each attack deliberately has its own visual topology.
   *
   * ARP:
   * Rogue host stays near the gateway because the important concept
   * is gateway impersonation/mapping deception.
   *
   * MITM:
   * Interceptor sits in the middle because the important concept
   * is traffic passing through an intermediary.
   *
   * Evil Twin:
   * Rogue AP stays beside the mobile device.
   *
   * DNS:
   * DNS injector stays between workstation and DNS resolver.
   */
  const attackerPosition =
    selectedAttack === "arp"
      ? { x: 69, y: 36 }
      : selectedAttack === "mitm"
        ? { x: 50, y: 49 }
        : selectedAttack === "eviltwin"
          ? { x: 91, y: 47 }
          : { x: 52, y: 49 };

  const showAttacker = stepIndex >= 0 && !contained;

  const arpAttackActive =
    selectedAttack === "arp" && stepIndex >= 1 && !contained;

  const mitmAttackActive =
    selectedAttack === "mitm" && stepIndex >= 1 && !contained;

  const evilTwinAttackActive =
    selectedAttack === "eviltwin" && stepIndex >= 2 && !contained;

  const dnsAttackActive =
    selectedAttack === "dns" && stepIndex >= 1 && !contained;

  return (
    <section className="space-y-4">
      <style>{`
        @keyframes attacklab-flow {
          from {
            stroke-dashoffset: 0;
          }
          to {
            stroke-dashoffset: -18;
          }
        }

        @keyframes attacklab-dot {
          0% {
            opacity: 0;
          }

          15% {
            opacity: 1;
          }

          85% {
            opacity: 1;
          }

          100% {
            opacity: 0;
          }
        }

        @keyframes attacklab-pulse {
          0%, 100% {
            opacity: .45;
            transform: scale(.96);
          }

          50% {
            opacity: 1;
            transform: scale(1);
          }
        }

        @keyframes attacklab-danger {
          0%, 100% {
            opacity: .35;
          }

          50% {
            opacity: .9;
          }
        }

        .attack-flow {
          animation: attacklab-flow 3.4s linear infinite;
        }

        .attack-dot {
          animation: attacklab-dot 2.4s ease-in-out infinite;
        }

        .attack-pulse {
          animation: attacklab-pulse 1.6s ease-in-out infinite;
        }

        .attack-danger {
          animation: attacklab-danger 1.1s ease-in-out infinite;
        }

        @media (prefers-reduced-motion: reduce) {
          .attack-flow,
          .attack-dot,
          .attack-pulse,
          .attack-danger {
            animation: none;
          }
        }
      `}</style>

      {/* Top controls */}
      <div className="flex flex-col gap-3 rounded-xl border border-border bg-card/40 p-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Beaker className="h-4 w-4 text-primary" />

            <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
              isolated simulation
            </span>

            <span className="rounded-full border border-safe/30 bg-safe/5 px-2 py-0.5 text-[9px] font-medium text-safe">
              REAL NETWORK UNTOUCHED
            </span>
          </div>

          <p className="mt-1 text-sm font-semibold">
            {ATTACKS.find((attack) => attack.id === selectedAttack)?.name}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {ATTACKS.map((attack) => (
            <button
              key={attack.id}
              type="button"
              disabled={running}
              onClick={() => {
                setChoice(attack.id);
                setActiveAttack(null);
                setStepIndex(-1);
              }}
              className={cn(
                "rounded-lg border px-3 py-2 text-xs font-medium transition-colors",
                selectedAttack === attack.id
                  ? "border-primary/50 bg-primary/10 text-primary"
                  : "border-border bg-background/40 text-muted-foreground hover:bg-muted/40",
                running && "cursor-not-allowed opacity-60",
              )}
            >
              {attack.name}
            </button>
          ))}

          <button
            type="button"
            onClick={startSimulation}
            disabled={running}
            className="inline-flex h-9 items-center gap-2 rounded-lg bg-primary px-3.5 text-xs font-semibold text-primary-foreground transition-colors hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            {running ? "Running..." : "Start Simulation"}
          </button>

          <button
            type="button"
            onClick={resetSimulation}
            className="inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-background/40 px-3.5 text-xs font-medium hover:bg-muted/40"
          >
            <Square className="h-3 w-3" />
            Reset
          </button>
        </div>
      </div>

      {/* Main workspace */}
      <div className="grid min-h-[600px] gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        {/* Network */}
        <div className="relative min-h-[600px] overflow-hidden rounded-xl border border-border bg-card/30">
          <div className="absolute left-4 right-4 top-4 z-10 flex items-start justify-between">
            <div>
              <p className="text-sm font-semibold">
                Simulated Network
              </p>

              <p className="mt-0.5 text-xs text-muted-foreground">
                3 simulated devices · isolated from real traffic
              </p>
            </div>

            <div
              className={cn(
                "rounded-full border px-3 py-1.5 font-mono text-[10px]",
                contained
                  ? "border-safe/30 bg-safe/5 text-safe"
                  : detected
                    ? "border-destructive/30 bg-destructive/5 text-destructive"
                    : "border-border bg-background/60 text-muted-foreground",
              )}
            >
              {progress}% ·{" "}
              {contained
                ? "CONTAINED"
                : detected
                  ? "THREAT DETECTED"
                  : running
                    ? "MONITORING"
                    : "STANDBY"}
            </div>
          </div>

          <svg
            viewBox="0 0 100 100"
            preserveAspectRatio="none"
            className="absolute inset-0 h-full w-full"
          >
            {/* ============================================================
                NORMAL NETWORK PATHS
            ============================================================ */}

            {/* Router → Workstation */}
            <line
              x1={DEVICES.router.x}
              y1={DEVICES.router.y}
              x2={DEVICES.workstation.x}
              y2={DEVICES.workstation.y}
              stroke="currentColor"
              strokeWidth="0.45"
              className={cn(
                "transition-all duration-700",
                mitmAttackActive || arpAttackActive || dnsAttackActive
                  ? "text-muted-foreground/20"
                  : "text-border",
              )}
            />

            {/* Router → Mobile */}
            <line
              x1={DEVICES.router.x}
              y1={DEVICES.router.y}
              x2={DEVICES.mobile.x}
              y2={DEVICES.mobile.y}
              stroke="currentColor"
              strokeWidth="0.45"
              className={cn(
                "transition-all duration-700",
                selectedAttack === "eviltwin" && evilTwinAttackActive
                  ? "text-muted-foreground/20"
                  : "text-border",
              )}
            />

            {/* DNS resolver path */}
            {selectedAttack === "dns" && (
              <line
                x1={DEVICES.router.x}
                y1={DEVICES.router.y}
                x2={DEVICES.dns.x}
                y2={DEVICES.dns.y}
                stroke="currentColor"
                strokeWidth="0.45"
                className="text-border"
              />
            )}

            {/* ============================================================
                ARP SPOOF
                Gateway identity deception.
            ============================================================ */}

            {arpAttackActive && (
              <>
                {/* Rogue host claims gateway relationship */}
                <line
                  x1={DEVICES.router.x}
                  y1={DEVICES.router.y}
                  x2={attackerPosition.x}
                  y2={attackerPosition.y}
                  stroke="currentColor"
                  strokeWidth="0.8"
                  strokeDasharray="2 2"
                  className={cn(
                    "attack-flow",
                    detected
                      ? "text-destructive"
                      : "text-primary",
                  )}
                />

                {/* Rogue mapping toward workstation */}
                <line
                  x1={attackerPosition.x}
                  y1={attackerPosition.y}
                  x2={DEVICES.workstation.x}
                  y2={DEVICES.workstation.y}
                  stroke="currentColor"
                  strokeWidth="0.8"
                  strokeDasharray="2 2"
                  className={cn(
                    "attack-flow",
                    detected
                      ? "text-destructive"
                      : "text-primary",
                  )}
                />
              </>
            )}

            {/* ARP gateway identity label */}
            {selectedAttack === "arp" &&
              stepIndex >= 1 &&
              !contained && (
                <g>
                  <rect
                    x="61"
                    y="22"
                    width="24"
                    height="7"
                    rx="2"
                    fill="currentColor"
                    className="text-background"
                    opacity="0.95"
                  />

                  <text
                    x="73"
                    y="26.7"
                    textAnchor="middle"
                    className={cn(
                      "fill-current text-[2.5px] font-semibold",
                      detected
                        ? "text-destructive"
                        : "text-primary",
                    )}
                  >
                    FAKE GATEWAY CLAIM
                  </text>
                </g>
              )}

            {/* ============================================================
                MITM
                Attacker physically/logically in the communication path.
            ============================================================ */}

            {mitmAttackActive && (
              <>
                <line
                  x1={DEVICES.router.x}
                  y1={DEVICES.router.y}
                  x2={attackerPosition.x}
                  y2={attackerPosition.y}
                  stroke="currentColor"
                  strokeWidth="0.9"
                  strokeDasharray="2 2"
                  className={cn(
                    "attack-flow",
                    detected
                      ? "text-destructive"
                      : "text-primary",
                  )}
                />

                <line
                  x1={attackerPosition.x}
                  y1={attackerPosition.y}
                  x2={DEVICES.workstation.x}
                  y2={DEVICES.workstation.y}
                  stroke="currentColor"
                  strokeWidth="0.9"
                  strokeDasharray="2 2"
                  className={cn(
                    "attack-flow",
                    detected
                      ? "text-destructive"
                      : "text-primary",
                  )}
                />
              </>
            )}

            {/* MITM interception label */}
            {selectedAttack === "mitm" &&
              stepIndex >= 2 &&
              !contained && (
                <g>
                  <rect
                    x="34"
                    y="31"
                    width="32"
                    height="7"
                    rx="2"
                    fill="currentColor"
                    className="text-background"
                    opacity="0.95"
                  />

                  <text
                    x="50"
                    y="35.7"
                    textAnchor="middle"
                    className={cn(
                      "fill-current text-[2.5px] font-semibold",
                      detected
                        ? "text-destructive"
                        : "text-primary",
                    )}
                  >
                    TRAFFIC INTERCEPTED
                  </text>
                </g>
              )}

            {/* ============================================================
                EVIL TWIN
                Mobile device attempts to associate with rogue AP.
            ============================================================ */}

            {selectedAttack === "eviltwin" &&
              evilTwinAttackActive && (
                <line
                  x1={DEVICES.mobile.x}
                  y1={DEVICES.mobile.y}
                  x2={attackerPosition.x}
                  y2={attackerPosition.y}
                  stroke="currentColor"
                  strokeWidth="0.9"
                  strokeDasharray="2 2"
                  className={cn(
                    "attack-flow",
                    detected
                      ? "text-destructive"
                      : "text-primary",
                  )}
                />
              )}

            {/* ============================================================
                DNS SPOOF
                Workstation ↔ DNS resolver with forged response.
            ============================================================ */}

            {selectedAttack === "dns" &&
              dnsAttackActive && (
                <>
                  {/* Workstation → DNS resolver */}
                  <line
                    x1={DEVICES.workstation.x}
                    y1={DEVICES.workstation.y}
                    x2={DEVICES.dns.x}
                    y2={DEVICES.dns.y}
                    stroke="currentColor"
                    strokeWidth="0.7"
                    strokeDasharray="2 2"
                    className="attack-flow text-primary"
                  />

                  {/* DNS injector → Workstation */}
                  <line
                    x1={attackerPosition.x}
                    y1={attackerPosition.y}
                    x2={DEVICES.workstation.x}
                    y2={DEVICES.workstation.y}
                    stroke="currentColor"
                    strokeWidth="0.9"
                    strokeDasharray="2 2"
                    className={cn(
                      "attack-flow",
                      detected
                        ? "text-destructive"
                        : "text-primary",
                    )}
                  />

                  {/* DNS injector → DNS resolver */}
                  <line
                    x1={attackerPosition.x}
                    y1={attackerPosition.y}
                    x2={DEVICES.dns.x}
                    y2={DEVICES.dns.y}
                    stroke="currentColor"
                    strokeWidth="0.6"
                    strokeDasharray="2 2"
                    className={cn(
                      "attack-flow",
                      detected
                        ? "text-destructive"
                        : "text-primary",
                    )}
                  />
                </>
              )}

            {/* DNS forged-response label */}
            {selectedAttack === "dns" &&
              stepIndex >= 1 &&
              !contained && (
                <g>
                  <rect
                    x="31"
                    y="55"
                    width="30"
                    height="7"
                    rx="2"
                    fill="currentColor"
                    className="text-background"
                    opacity="0.95"
                  />

                  <text
                    x="46"
                    y="59.7"
                    textAnchor="middle"
                    className={cn(
                      "fill-current text-[2.5px] font-semibold",
                      detected
                        ? "text-destructive"
                        : "text-primary",
                    )}
                  >
                    FORGED DNS RESPONSE
                  </text>
                </g>
              )}

            {/* ============================================================
                PACKET ANIMATION
            ============================================================ */}

            {running && !contained && (
              <>
                {/* ARP packets */}
                {selectedAttack === "arp" && (
                  <>
                    <circle
                      r="1.1"
                      fill="currentColor"
                      className={cn(
                        "attack-dot",
                        detected
                          ? "text-destructive"
                          : "text-primary",
                      )}
                    >
                      <animateMotion
                        key={`arp-forward-${stepIndex < 2 ? "normal" : "spoof"}`}
                        dur="4.0s"
                        repeatCount="indefinite"
                        path={
                          stepIndex < 2
                            ? "M 50 23 L 22 72"
                            : "M 22 72 L 69 36"
                        }
                      />
                    </circle>

                    <circle
                      r="0.8"
                      fill="currentColor"
                      className={cn(
                        "attack-dot",
                        detected
                          ? "text-destructive"
                          : "text-primary",
                      )}
                    >
                      <animateMotion
                        key={`arp-return-${stepIndex < 2 ? "normal" : "spoof"}`}
                        dur="4.0s"
                        begin="0.8s"
                        repeatCount="indefinite"
                        path={
                          stepIndex < 2
                            ? "M 22 72 L 50 23"
                            : "M 69 36 L 22 72"
                        }
                      />
                    </circle>
                  </>
                )}

                {/* MITM packets */}
                {selectedAttack === "mitm" && (
                  <>
                    <circle
                      r="1.1"
                      fill="currentColor"
                      className={cn(
                        "attack-dot",
                        detected
                          ? "text-destructive"
                          : "text-primary",
                      )}
                    >
                      <animateMotion
                        key={`mitm-forward-${stepIndex < 2 ? "normal" : "attack"}`}
                        dur="4.0s"
                        repeatCount="indefinite"
                        path={
                          stepIndex < 2
                            ? "M 50 23 L 22 72"
                            : "M 50 23 L 50 49 L 22 72"
                        }
                      />
                    </circle>

                    <circle
                      r="0.8"
                      fill="currentColor"
                      className={cn(
                        "attack-dot",
                        detected
                          ? "text-destructive"
                          : "text-primary",
                      )}
                    >
                      <animateMotion
                        key={`mitm-return-${stepIndex < 2 ? "normal" : "attack"}`}
                        dur="4.0s"
                        begin="0.8s"
                        repeatCount="indefinite"
                        path={
                          stepIndex < 2
                            ? "M 22 72 L 50 23"
                            : "M 22 72 L 50 49 L 50 23"
                        }
                      />
                    </circle>
                  </>
                )}

                {/* Evil Twin packets */}
                {selectedAttack === "eviltwin" && (
                  <>
                    <circle
                      r="1.1"
                      fill="currentColor"
                      className={cn(
                        "attack-dot",
                        detected
                          ? "text-destructive"
                          : "text-primary",
                      )}
                    >
                      <animateMotion
                        key={`evil-forward-${stepIndex}`}
                        dur="4.0s"
                        repeatCount="indefinite"
                        path={
                          stepIndex < 2
                            ? "M 50 23 L 78 72"
                            : "M 78 72 L 91 47"
                        }
                      />
                    </circle>

                    <circle
                      r="0.8"
                      fill="currentColor"
                      className={cn(
                        "attack-dot",
                        detected
                          ? "text-destructive"
                          : "text-primary",
                      )}
                    >
                      <animateMotion
                        key={`evil-return-${stepIndex}`}
                        dur="4.0s"
                        begin="0.8s"
                        repeatCount="indefinite"
                        path={
                          stepIndex < 2
                            ? "M 78 72 L 50 23"
                            : "M 91 47 L 78 72"
                        }
                      />
                    </circle>
                  </>
                )}

                {/* DNS packets */}
                {selectedAttack === "dns" && (
                  <>
                    <circle
                      r="1.1"
                      fill="currentColor"
                      className={cn(
                        "attack-dot",
                        detected
                          ? "text-destructive"
                          : "text-primary",
                      )}
                    >
                      <animateMotion
                        key={`dns-request-${stepIndex}`}
                        dur="4.0s"
                        repeatCount="indefinite"
                        path={
                          stepIndex < 1
                            ? "M 22 72 L 78 34"
                            : "M 22 72 L 52 49"
                        }
                      />
                    </circle>

                    <circle
                      r="0.8"
                      fill="currentColor"
                      className={cn(
                        "attack-dot",
                        detected
                          ? "text-destructive"
                          : "text-primary",
                      )}
                    >
                      <animateMotion
                        key={`dns-response-${stepIndex}`}
                        dur="4.0s"
                        begin="0.8s"
                        repeatCount="indefinite"
                        path={
                          stepIndex < 1
                            ? "M 78 34 L 22 72"
                            : "M 78 34 L 52 49 L 22 72"
                        }
                      />
                    </circle>
                  </>
                )}
              </>
            )}
          </svg>

          {/* Router */}
          <div
            className="absolute -translate-x-1/2 -translate-y-1/2 text-center"
            style={{
              left: `${DEVICES.router.x}%`,
              top: `${DEVICES.router.y}%`,
            }}
          >
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border border-border bg-card shadow-sm">
              <Router className="h-6 w-6 text-muted-foreground" />
            </div>

            <p className="mt-2 text-xs font-semibold">
              Gateway Router
            </p>

            <p className="font-mono text-[10px] text-muted-foreground">
              {DEVICES.router.ip}
            </p>

            {selectedAttack === "arp" &&
              stepIndex >= 1 &&
              !contained && (
                <div
                  className={cn(
                    "mt-1 text-[9px] font-medium",
                    detected
                      ? "text-destructive"
                      : "text-primary",
                  )}
                >
                  Gateway identity challenged
                </div>
              )}
          </div>

          {/* Workstation */}
          <div
            className="absolute -translate-x-1/2 -translate-y-1/2 text-center"
            style={{
              left: `${DEVICES.workstation.x}%`,
              top: `${DEVICES.workstation.y}%`,
            }}
          >
            <div
              className={cn(
                "relative mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border bg-card shadow-sm transition-all duration-500",
                scenario.target === "Workstation" &&
                  detected &&
                  !contained
                  ? "border-destructive/60 bg-destructive/5"
                  : "border-border",
              )}
            >
              {scenario.target === "Workstation" &&
                detected &&
                !contained && (
                  <span className="attack-danger absolute -inset-2 rounded-2xl border border-destructive/40" />
                )}

              <Laptop
                className={cn(
                  "relative h-6 w-6",
                  scenario.target === "Workstation" &&
                    detected &&
                    !contained
                    ? "text-destructive"
                    : "text-muted-foreground",
                )}
              />
            </div>

            <p className="mt-2 text-xs font-semibold">
              Workstation
            </p>

            <p className="font-mono text-[10px] text-muted-foreground">
              {DEVICES.workstation.ip}
            </p>
          </div>

          {/* Mobile */}
          <div
            className="absolute -translate-x-1/2 -translate-y-1/2 text-center"
            style={{
              left: `${DEVICES.mobile.x}%`,
              top: `${DEVICES.mobile.y}%`,
            }}
          >
            <div
              className={cn(
                "relative mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border bg-card shadow-sm transition-all duration-500",
                scenario.target === "Mobile Device" &&
                  detected &&
                  !contained
                  ? "border-destructive/60 bg-destructive/5"
                  : "border-border",
              )}
            >
              {scenario.target === "Mobile Device" &&
                detected &&
                !contained && (
                  <span className="attack-danger absolute -inset-2 rounded-2xl border border-destructive/40" />
                )}

              <Smartphone
                className={cn(
                  "relative h-6 w-6",
                  scenario.target === "Mobile Device" &&
                    detected &&
                    !contained
                    ? "text-destructive"
                    : "text-muted-foreground",
                )}
              />
            </div>

            <p className="mt-2 text-xs font-semibold">
              Mobile Device
            </p>

            <p className="font-mono text-[10px] text-muted-foreground">
              {DEVICES.mobile.ip}
            </p>
          </div>

          {/* DNS Resolver */}
          {selectedAttack === "dns" && (
            <div
              className="absolute -translate-x-1/2 -translate-y-1/2 text-center"
              style={{
                left: `${DEVICES.dns.x}%`,
                top: `${DEVICES.dns.y}%`,
              }}
            >
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-border bg-card shadow-sm">
                <Server className="h-5 w-5 text-muted-foreground" />
              </div>

              <p className="mt-2 text-xs font-semibold">
                DNS Resolver
              </p>

              <p className="font-mono text-[10px] text-muted-foreground">
                {DEVICES.dns.ip}
              </p>
            </div>
          )}

          {/* Simulated attacker */}
          {showAttacker && (
            <div
              className="absolute -translate-x-1/2 -translate-y-1/2 text-center transition-all duration-[1800ms] ease-in-out"
              style={{
                left: `${attackerPosition.x}%`,
                top: `${attackerPosition.y}%`,
              }}
            >
              <div
                className={cn(
                  "relative mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border bg-destructive/5",
                  detected
                    ? "border-destructive/70"
                    : "border-primary/50",
                )}
              >
                <span
                  className={cn(
                    "absolute -inset-2 rounded-2xl border",
                    detected
                      ? "attack-danger border-destructive/40"
                      : "border-primary/20",
                  )}
                />

                {selectedAttack === "eviltwin" ? (
                  <Wifi
                    className={cn(
                      "relative h-6 w-6",
                      detected
                        ? "text-destructive"
                        : "text-primary",
                    )}
                  />
                ) : (
                  <Zap
                    className={cn(
                      "relative h-6 w-6",
                      detected
                        ? "text-destructive"
                        : "text-primary",
                    )}
                  />
                )}
              </div>

              <p
                className={cn(
                  "mt-2 text-xs font-semibold",
                  detected
                    ? "text-destructive"
                    : "text-primary",
                )}
              >
                {selectedAttack === "eviltwin"
                  ? "EVIL TWIN AP"
                  : scenario.attacker}
              </p>

              <p className="font-mono text-[10px] text-muted-foreground">
                {scenario.attackerIp}
              </p>
            </div>
          )}

          {/* Detection */}
          {detected && !contained && (
            <div className="absolute bottom-4 left-4 flex items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              <AlertTriangle className="h-3.5 w-3.5" />

              WiFi Guard detected abnormal behaviour
            </div>
          )}

          {/* Containment */}
          {contained && (
            <div className="absolute bottom-4 left-4 flex items-center gap-2 rounded-lg border border-safe/40 bg-safe/10 px-3 py-2 text-xs text-safe">
              <CheckCircle2 className="h-3.5 w-3.5" />

              Normal network path restored
            </div>
          )}

          {/* Standby */}
          {!running && stepIndex < 0 && (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="rounded-xl border border-border bg-background/80 px-5 py-4 text-center backdrop-blur-sm">
                <p className="text-sm font-semibold">
                  Ready for demonstration
                </p>

                <p className="mt-1 text-xs text-muted-foreground">
                  Start the simulation to watch the attack unfold.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Right panel */}
        <aside className="flex min-h-[600px] flex-col rounded-xl border border-border bg-card/40 p-5">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-safe" />

            <p className="text-sm font-semibold">
              Attack Status
            </p>
          </div>

          <div className="mt-5 rounded-lg border border-border bg-background/40 p-4">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
              {currentStep
                ? `Step ${stepIndex + 1} / ${scenario.steps.length}`
                : "Simulation"}
            </p>

            <p className="mt-1 text-lg font-semibold leading-tight">
              {currentStep?.title ?? "Ready"}
            </p>

            <p className="mt-2 text-xs leading-5 text-muted-foreground">
              {currentStep?.event ??
                "Start the simulation to see what the attacker does and how WiFi Guard responds."}
            </p>
          </div>

          <div className="mt-4 rounded-lg border border-border bg-background/40 p-4">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />

              <p className="text-xs font-semibold uppercase tracking-wide">
                What's happening?
              </p>
            </div>

            <p className="mt-3 text-sm leading-6">
              {currentStep?.explanation ??
                "The right panel explains every stage while the network graph shows the corresponding simulated activity."}
            </p>
          </div>

          <div className="mt-4 space-y-3">
            <div className="rounded-lg border border-border bg-background/30 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Target
              </p>

              <div className="mt-1.5 flex items-center gap-2">
                <Target className="h-4 w-4 text-muted-foreground" />

                <div>
                  <p className="text-sm font-medium">
                    {scenario.target}
                  </p>

                  <p className="font-mono text-[10px] text-muted-foreground">
                    {scenario.targetIp}
                  </p>
                </div>
              </div>
            </div>

            <div className="rounded-lg border border-border bg-background/30 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Simulated attacker
              </p>

              <div className="mt-1.5 flex items-center gap-2">
                {selectedAttack === "eviltwin" ? (
                  <Wifi className="h-4 w-4 text-destructive" />
                ) : (
                  <Zap className="h-4 w-4 text-destructive" />
                )}

                <div>
                  <p className="text-sm font-medium">
                    {scenario.attacker}
                  </p>

                  <p className="font-mono text-[10px] text-muted-foreground">
                    {scenario.attackerIp}
                  </p>
                </div>
              </div>
            </div>

            <div className="rounded-lg border border-border bg-background/30 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Packet activity
              </p>

              <p className="mt-1.5 text-sm font-medium">
                {currentStep?.packet ?? "Waiting for simulation"}
              </p>
            </div>
          </div>

          <div className="mt-auto pt-4">
            <div
              className={cn(
                "rounded-lg border p-4",
                contained
                  ? "border-safe/30 bg-safe/5"
                  : detected
                    ? "border-destructive/30 bg-destructive/5"
                    : "border-border bg-background/30",
              )}
            >
              <div className="flex items-center gap-2">
                {contained ? (
                  <CheckCircle2 className="h-4 w-4 text-safe" />
                ) : detected ? (
                  <AlertTriangle className="h-4 w-4 text-destructive" />
                ) : (
                  <Radio className="h-4 w-4 text-muted-foreground" />
                )}

                <p className="text-sm font-semibold">
                  {contained
                    ? "Simulation contained"
                    : detected
                      ? "Threat identified"
                      : "Defender monitoring"}
                </p>
              </div>

              <p className="mt-2 text-xs leading-5 text-muted-foreground">
                {currentStep?.defender ??
                  "WiFi Guard is waiting for the simulated attack to begin."}
              </p>
            </div>
          </div>
        </aside>
      </div>

      {/* Timeline */}
      <div className="rounded-xl border border-border bg-card/40 p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold">
              Attack Timeline
            </p>

            <p className="mt-0.5 text-xs text-muted-foreground">
              Follow the attack from the first event to containment.
            </p>
          </div>

          <span className="font-mono text-[10px] uppercase tracking-wide text-muted-foreground">
            {stepIndex >= 0
              ? `${stepIndex + 1} / ${scenario.steps.length}`
              : `0 / ${scenario.steps.length}`}
          </span>
        </div>

        <div className="mt-4 overflow-x-auto pb-1">
          <div className="flex min-w-[760px] items-start">
            {timeline.map((step, index) => (
              <div
                key={step.title}
                className="flex min-w-[150px] flex-1 items-start"
              >
                <div className="flex flex-1 flex-col items-center">
                  <div
                    className={cn(
                      "flex h-9 w-9 items-center justify-center rounded-full border text-xs font-semibold transition-all duration-500",
                      step.current
                        ? "border-primary bg-primary/10 text-primary shadow-sm"
                        : step.complete
                          ? "border-safe/40 bg-safe/10 text-safe"
                          : "border-border bg-background text-muted-foreground",
                    )}
                  >
                    {step.complete ? (
                      <CheckCircle2 className="h-4 w-4" />
                    ) : (
                      index + 1
                    )}
                  </div>

                  <p
                    className={cn(
                      "mt-2 text-center text-xs font-medium",
                      step.current
                        ? "text-primary"
                        : step.complete
                          ? "text-safe"
                          : "text-muted-foreground",
                    )}
                  >
                    {step.title}
                  </p>

                  <p className="mt-1 max-w-[130px] text-center text-[10px] leading-4 text-muted-foreground">
                    {step.event}
                  </p>
                </div>

                {index < timeline.length - 1 && (
                  <div
                    className={cn(
                      "mt-[18px] h-px flex-1 transition-colors duration-500",
                      step.complete
                        ? "bg-safe/50"
                        : "bg-border",
                    )}
                  />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Safety note */}
      <div className="flex items-start gap-3 rounded-lg border border-border bg-muted/20 px-4 py-3">
        <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />

        <p className="text-xs leading-5 text-muted-foreground">
          <span className="font-medium text-foreground">
            Safe demonstration:
          </span>{" "}
          Attack Lab uses simulated devices, packets and attack states only.
          It does not send ARP spoofing packets, intercept real traffic,
          create access points, modify DNS or attack your real network.
        </p>
      </div>
    </section>
  );
}
