"use client";

import { useApiHealth } from "@/contexts/ApiHealthContext";

export function TopBar() {
  const { status, lastChecked } = useApiHealth();

  return (
    <header className="h-12 border-b border-border bg-background flex items-center justify-between px-6 shrink-0 font-sans">
      <div className="flex items-center gap-3">
        <span className="font-semibold text-xs tracking-widest text-muted-foreground uppercase">SOC Triage</span>
        <span className="text-border">/</span>
        <span className="font-medium text-xs text-foreground">Operational Environment</span>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2" aria-live="polite">
          <div
            className={`w-2 h-2 rounded-full ${
              status === "ONLINE" ? "bg-success" : status === "OFFLINE" ? "bg-destructive" : "bg-muted animate-pulse"
            }`}
          />
          <span className={`text-[11px] font-bold uppercase tracking-widest ${
            status === "ONLINE" ? "text-success" : status === "OFFLINE" ? "text-destructive" : "text-muted-foreground"
          }`}>
            {status === "ONLINE" ? "API ONLINE" : status === "OFFLINE" ? "API OFFLINE" : "CHECKING STATUS"}
          </span>
        </div>
        <span className="text-border text-xs">|</span>
        <span className="text-[11px] font-mono text-muted-foreground tracking-widest tabular-nums" aria-live="polite">
          LAST SYNC: {lastChecked || "--:--"}
        </span>
      </div>
    </header>
  );
}
