import { useEffect, useRef, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Bot, FileText, Sparkles } from "lucide-react";
import jsPDF from "jspdf";
import { useNetwork } from "@/lib/network-sim";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/assistant")({
  validateSearch: (s: Record<string, unknown>) => ({
    device: typeof s["device"] === "string" ? s["device"] : undefined,
    event: typeof s["event"] === "string" ? s["event"] : undefined,
  }),
  head: () => ({
    meta: [
      { title: "AI Analyst — WiFi Guard" },
      {
        name: "description",
        content:
          "A plain-language analyst that explains network health, detected threats and defensive actions, and writes full reports.",
      },
      { property: "og:title", content: "AI Analyst — WiFi Guard" },
      {
        property: "og:description",
        content: "Understand what your network is doing, explained in plain language.",
      },
    ],
  }),
  component: Assistant,
});

function Assistant() {
  const { device: deviceId, event: eventId } = Route.useSearch();
  const { state } = useNetwork();
  const [report, setReport] = useState(false);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");
  const [loading, setLoading] = useState(false);
  const [aiError, setAiError] = useState("");
  const device = deviceId ? state.devices.find((d) => d.id === deviceId) : undefined;
  const event = eventId
    ? state.events.find((e) => String(e.id) === eventId) ?? {
        label: eventId,
        detail: "This threat was detected by WiFi Guard.",
        time: "Now",
      }
    : undefined;
  const totalDown = state.devices.reduce((a, d) => a + d.down, 0);
  const threats = state.events.filter((e) => e.severity === "danger" || e.severity === "warn");
  const [messages, setMessages] = useState<
    { role: "user" | "assistant"; text: string }[]
  >([]);
  const generatePDFReport = () => {
    const pdf = new jsPDF();

    pdf.setFontSize(22);
    pdf.setFont("helvetica", "bold");
    pdf.text("WIFI GUARD", 20, 20);

    pdf.setFontSize(12);
    pdf.setFont("helvetica", "normal");
    pdf.text("NETWORK SECURITY REPORT", 20, 29);

    pdf.setFontSize(9);
    pdf.setTextColor(100, 100, 100);
    pdf.text(
      `Network: GUARDNET-5G   •   Status: ${state.status}`,
      20,
      37,
    );

    pdf.setTextColor(0, 0, 0);
    pdf.setDrawColor(180, 180, 180);
    pdf.line(20, 43, 190, 43);

    const reportDate = new Date().toLocaleString();

    pdf.setFontSize(9);
    pdf.setTextColor(100, 100, 100);
    pdf.text(`Generated: ${reportDate}`, 20, 50);

    pdf.setTextColor(0, 0, 0);

    let y = 100;

    pdf.setFontSize(14);
    pdf.setFont("helvetica", "bold");
    pdf.text("NETWORK OVERVIEW", 20, y);

    pdf.setFont("helvetica", "normal");
    y += 10;

    pdf.setFontSize(10);
    pdf.text(
      `Combined download traffic: ${totalDown.toFixed(0)} Mbps`,
      20,
      y,
    );
    y += 7;

    pdf.text(
      `Threat events detected: ${threats.length}`,
      20,
      y,
    );
    y += 15;

    pdf.setFontSize(14);
    pdf.text("Devices", 20, y);
    y += 10;

    pdf.setFontSize(10);

    pdf.setFont("helvetica", "bold");
    pdf.text("Device", 20, y);
    pdf.text("IP Address", 85, y);
    pdf.text("Download", 135, y);
    pdf.text("Latency", 170, y);

    y += 6;
    pdf.setFont("helvetica", "normal");

    state.devices.forEach((d) => {
      pdf.text(d.name, 20, y);
      pdf.text(d.ip, 85, y);
      pdf.text(`${d.down.toFixed(1)} Mbps`, 135, y);
      pdf.text(`${d.latency.toFixed(0)} ms`, 170, y);

      y += 7;

      if (y > 270) {
        pdf.addPage();
        y = 20;
      }
    });

    y += 8;

    pdf.setFontSize(14);
    pdf.setFont("helvetica", "bold");
    pdf.text("THREAT ACTIVITY", 20, y);

    pdf.setFont("helvetica", "normal");
    y += 10;

    pdf.setFontSize(10);

    if (threats.length === 0) {
      pdf.text("No threat events were detected.", 20, y);
      y += 7;
    } else {
      threats.slice(-6).forEach((e) => {
        pdf.text(`${e.time} — ${e.label}`, 20, y);
        y += 7;

        if (y > 270) {
          pdf.addPage();
          y = 20;
        }
      });
    }

    y += 8;

    pdf.setFontSize(14);
    pdf.setFont("helvetica", "bold");
    pdf.text("RECOMMENDATIONS", 20, y);

    pdf.setFont("helvetica", "normal");
    y += 10;

    pdf.setFontSize(10);

    [
      "Keep Threat Defender monitoring enabled.",
      "Keep connected devices and router firmware updated.",
      "Quarantine devices that cannot be identified or trusted.",
    ].forEach((recommendation) => {
      pdf.text(`• ${recommendation}`, 20, y);
      y += 7;
    });

    pdf.save("wifi-guard-network-report.pdf");
  };


  const askAI = async (aiQuestion?: string) => {
    const trimmedQuestion = (aiQuestion ?? question).trim();

    if (!trimmedQuestion || loading) return;

    setLoading(true);
    setAiError("");


    try {
      const response = await fetch("https://wifi-guard-production.up.railway.app/ai/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          question: trimmedQuestion,
          conversation: messages,
        }),
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "AI request failed.");
      }

      setAnswer(data.answer);

      setMessages((previous) => [
        
        { role: "user", text: trimmedQuestion },
        { role: "assistant", text: data.answer },
        ...previous,
      ]);
      setQuestion("");
    } catch (error) {
      setAiError(
        error instanceof Error
          ? error.message
          : "Unable to reach the AI assistant.",
      );
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    if (eventId && !loading && messages.length === 0) {
      void askAI(
        `Explain this detected WiFi Guard threat in simple terms: ${eventId}`
      );
    }
  }, [eventId]);
  return (
    <div className="mx-auto max-w-4xl px-6 py-8">
      <header>
        <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-muted-foreground">
          analyst
        </p>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">AI Assistant</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Continuous plain-language interpretation of what your network is doing.
        </p>
      </header>
      <section className="panel mt-6 p-5">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-primary" />
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
            ask WiFi Guard
          </p>
        </div>

        <div className="mt-4 flex gap-2">
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                void askAI();
              }
            }}
            placeholder="Why is my network warning me?"
            className="min-w-0 flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:border-primary"
          />

          <button
            type="button"
            onClick={() => void askAI()}
            disabled={loading || !question.trim()}
            className="rounded-md bg-primary px-4 py-2 text-xs font-medium text-primary-foreground transition-opacity disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? "Thinking..." : "Ask"}
          </button>
        </div>

        {aiError && (
          <p className="mt-3 text-xs text-danger">
            {aiError}
          </p>
        )}

        {messages.length > 0 && (
          <div className="mt-4 max-h-[420px] space-y-3 overflow-y-auto pr-2">
            {messages.map((message, index) => (
              <div
                key={`${message.role}-${index}`}
                className={cn(
                  "max-w-[85%] rounded-2xl px-4 py-3",
                  message.role === "user"
                    ? "ml-auto bg-slate-700 text-white"
                    : "mr-auto bg-muted text-foreground",
                )}
              >
                <p className="mb-1 font-mono text-[9px] uppercase tracking-[0.18em] text-muted-foreground">
                  {message.role === "user" ? "You" : "WiFi Guard AI"}
                </p>

                <p className="whitespace-pre-wrap text-sm leading-relaxed text-foreground">
                  {message.text}
                </p>
              </div>
            ))}

          </div>
        )}
      </section>

      <section className="panel mt-6 p-5">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-primary" />
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
            live explanation
          </p>
          <span
            className={cn(
              "ml-auto rounded-full px-2 py-0.5 font-mono text-[10px] uppercase",
              state.status === "SAFE"
                ? "bg-safe/15 text-safe"
                : state.status === "WARNING"
                  ? "bg-warn/15 text-warn"
                  : "bg-danger/15 text-danger",
            )}
          >
            {state.status}
          </span>
        </div>
        <p className="mt-4 text-[15px] leading-relaxed text-foreground">
          {device
            ? `WiFi Guard is currently explaining ${device.name} (${device.ip}). ${device.hostile
              ? "This device is currently flagged as hostile because its network behaviour does not match a normal client."
              : "This device is currently operating within its learned network behaviour and is not showing signs of hostile activity."
            }`
            : event
              ? `WiFi Guard is currently explaining the event "${event.label}". ${event.detail}`
              : "WiFi Guard is monitoring your current network and analyzing the devices and traffic detected by the latest scan."}
        </p>

        <div className="mt-5 border-t border-border pt-4">
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
            live reactions
          </p>
          <ul className="mt-3 space-y-2.5">
            <li className="flex gap-3 text-sm">
              <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-safe" />
              <span className="flex-1 leading-relaxed text-muted-foreground">
                WiFi Guard is monitoring the devices detected by the latest network scan.
              </span>
            </li>
          </ul>
        </div>
      </section>

      {event && (
        <section className="panel mt-4 border-primary/40 p-5">
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
            explaining event · {event.time}
          </p>
          <h2 className="mt-2 text-base font-semibold">{event.label}</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            {event.detail}. {explainEvent(event.label)}
          </p>
        </section>
      )}



      <section className="panel mt-4 p-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-primary" />
            <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
              network report
            </p>
          </div>
          <button
            onClick={() => {
              setReport(true);
              generatePDFReport();
            }}
            className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground transition-opacity hover:opacity-90"
          >
            Generate report
          </button>
        </div>

        {report ? (
          <article className="mt-5 space-y-5 text-sm leading-relaxed">
            <div>
              <h3 className="font-semibold">Summary</h3>
              <p className="mt-1 text-muted-foreground">
                Over the observed window the network carried roughly {totalDown.toFixed(0)} Mbps of
                combined traffic across {state.devices.length} devices. The current verdict is{" "}
                {state.status.toLowerCase()} with a Threat Confidence of {Math.round(state.threat)}%.
              </p>
            </div>
            <div>
              <h3 className="font-semibold">Detected attacks</h3>
              {threats.length ? (
                <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
                  {threats.slice(-6).map((e) => (
                    <li key={e.id}>
                      {e.time} — {e.label}: {e.detail}.
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-1 text-muted-foreground">
                  No attacks were observed in this window. The ARP table matched the learned
                  baseline throughout.
                </p>
              )}
            </div>
            <div>
              <h3 className="font-semibold">Health statistics</h3>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
                {[...state.devices]
                  .sort((a, b) => b.down - a.down)
                  .map((d) => (
                    <li key={d.id}>
                      {d.name}: {d.down.toFixed(1)} Mbps down, {d.latency.toFixed(0)} ms latency,{" "}
                      {d.signal.toFixed(0)}% signal.
                    </li>
                  ))}
              </ul>
            </div>
            <div>
              <h3 className="font-semibold">Recommendations</h3>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
                <li>Pin the gateway MAC address so poisoned ARP replies are ignored outright.</li>
                <li>Move the weakest-signal device closer to the router or add a mesh point.</li>
                <li>Quarantine any host that cannot be matched to a known vendor.</li>
              </ul>
            </div>
          </article>
        ) : (
          <p className="mt-4 flex items-center gap-2 text-sm text-muted-foreground">
            <Bot className="h-4 w-4" /> Generate a full write-up of activity, attacks, health and
            recommendations.
          </p>
        )}
      </section>
    </div>
  );
}

function explainEvent(label: string) {
  if (label.includes("ARP request"))
    return "Sweeping the whole subnet with ARP requests is how an attacker maps which devices exist before choosing a target.";
  if (label.includes("Suspicious ARP"))
    return "A device answered an address question it was never asked, which is the standard opening move of ARP spoofing.";
  if (label.includes("Gateway MAC"))
    return "When the gateway's hardware address changes without a router reboot, traffic is almost certainly being routed through an attacker.";
  if (label.includes("Defense"))
    return "Host-side protection rejected the poisoned entry and pinned the genuine gateway, so your traffic went back to the real router.";
  if (label.includes("stabilised"))
    return "All links returned to their learned baselines and Threat Confidence recovered.";
  return "This is routine network bookkeeping and requires no action.";
}
