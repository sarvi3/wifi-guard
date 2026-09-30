import { createFileRoute } from "@tanstack/react-router";
import { AttackLab } from "@/components/AttackLab";

export const Route = createFileRoute("/attack-lab")({
  component: AttackLabPage,
});

function AttackLabPage() {
  return (
    <div className="h-[calc(100vh-3.5rem)] overflow-auto">
      <div className="border-b border-border px-6 py-5">
        <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
          attack lab
        </p>

        <h1 className="mt-1 text-xl font-semibold tracking-tight">
          Security Attack Simulator
        </h1>

        <p className="mt-1 max-w-2xl text-xs text-muted-foreground">
          Safely simulate common Wi-Fi attack scenarios without affecting the
          real network.
        </p>
      </div>

      <div className="p-6">
        <AttackLab />
      </div>
    </div>
  );
}