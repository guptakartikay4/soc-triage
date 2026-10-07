"use client";

import { Suspense, useCallback } from "react";
import Link from "next/link";
import { useRouter, useSearchParams, usePathname } from "next/navigation";
import { incidentsApi } from "@/lib/api/incidents";
import { metricsApi } from "@/lib/api/metrics";
import { useResource } from "@/lib/hooks/useResource";
import { formatTime } from "@/lib/format";
import { PriorityTag } from "@/components/ui/priority-tag";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { ChevronLeft, ChevronRight, RefreshCw, AlertTriangle } from "lucide-react";

const limit = 50;

function IncidentsQueueContent() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  
  const pageStr = searchParams.get("page");
  const page = pageStr ? parseInt(pageStr, 10) : 1;
  const priority = searchParams.get("priority") || "ALL";

  const updateFilters = useCallback((newPriority: string, newPage: number) => {
    const params = new URLSearchParams(searchParams.toString());
    if (newPriority === "ALL") {
      params.delete("priority");
    } else {
      params.set("priority", newPriority);
    }
    if (newPage === 1) {
      params.delete("page");
    } else {
      params.set("page", newPage.toString());
    }
    router.push(`${pathname}?${params.toString()}`);
  }, [searchParams, pathname, router]);

  const { data: metricsData } = useResource(() => metricsApi.getOverview());
  const { data: incidents, error, loading, refetch } = useResource(
    (signal) => {
      const offset = (page - 1) * limit;
      const params: Record<string, string | number> = { limit, offset };
      if (priority !== "ALL") params.priority = priority;
      // Note: ignoring signal in this simple wrapper for the hackathon, but useResource handles aborts on the hook side.
      return incidentsApi.list(params);
    },
    [page, priority]
  );

  // Compute total for pagination
  let currentTotal = metricsData?.total_incidents || 0;
  if (metricsData) {
    if (priority === "P1") currentTotal = metricsData.critical_incidents;
    if (priority === "P2") currentTotal = metricsData.high_incidents;
    if (priority === "P3") currentTotal = metricsData.medium_incidents;
    if (priority === "P4") currentTotal = metricsData.low_incidents;
  }

  // Helper for actual status display mapping
  const formatStatus = (action: string | null) => {
    if (!action) return "NEW";
    const a = action.toUpperCase();
    if (a === "CONFIRM" || a === "INVESTIGATE") return "CONFIRMED";
    if (a === "ESCALATE") return "ESCALATED";
    if (a === "DISMISS") return "DISMISSED";
    return a;
  };

  return (
    <div className="space-y-4 animate-in fade-in duration-500 flex flex-col h-[calc(100vh-6rem)]">
      
      {/* HEADER & FILTER BAR */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 shrink-0">
        <div>
          <h1 className="text-2xl font-bold tracking-tight uppercase">Incident Queue</h1>
          <p className="text-xs text-muted-foreground mt-1 font-mono">{metricsData?.total_incidents || 0} correlated security incidents</p>
        </div>
        
        <div className="flex items-center gap-2 text-xs font-mono">
          <Select value={priority} onValueChange={(v) => updateFilters(v || "ALL", 1)}>
            <SelectTrigger className="w-[140px] h-8 bg-background border-border rounded-sm text-xs">
              <SelectValue placeholder="Priority" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">All Priorities</SelectItem>
              <SelectItem value="P1">P1 Critical</SelectItem>
              <SelectItem value="P2">P2 High</SelectItem>
              <SelectItem value="P3">P3 Medium</SelectItem>
              <SelectItem value="P4">P4 Low</SelectItem>
            </SelectContent>
          </Select>

          <Button variant="outline" size="sm" className="h-8 w-8 p-0 rounded-sm" onClick={() => refetch()} disabled={loading}>
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </div>

      {/* QUEUE SUMMARY */}
      <div className="flex items-center gap-4 text-[11px] font-mono tracking-widest uppercase border-y border-border py-2 shrink-0">
        <span className="text-muted-foreground">QUEUE SUMMARY:</span>
        <div className="flex gap-4">
          <span className="text-p1 font-bold">P1 <span className="text-foreground">{metricsData?.critical_incidents || 0}</span></span>
          <span className="text-p2 font-bold">P2 <span className="text-foreground">{metricsData?.high_incidents || 0}</span></span>
          <span className="text-p3 font-bold">P3 <span className="text-foreground">{metricsData?.medium_incidents || 0}</span></span>
          <span className="text-p4 font-bold">P4 <span className="text-foreground">{metricsData?.low_incidents || 0}</span></span>
        </div>
      </div>

      {/* TABLE */}
      <div className="flex-1 flex flex-col bg-card border border-border rounded-sm overflow-hidden">
        <div className="flex-1 overflow-auto">
          {error ? (
            <div className="flex flex-col items-center justify-center h-full text-center space-y-4">
              <AlertTriangle className="w-12 h-12 text-destructive" />
              <h2 className="text-lg font-semibold">{error.message}</h2>
              <Button variant="outline" onClick={() => refetch()}>Retry</Button>
            </div>
          ) : (
            <div className="w-full text-xs font-mono min-w-[800px] flex flex-col">
              <div className="sticky top-0 bg-muted/90 backdrop-blur z-10 border-b border-border flex text-left text-muted-foreground text-[11px] uppercase tracking-widest font-sans font-bold">
                <div className="px-4 py-2 w-16">PRI</div>
                <div className="px-4 py-2 w-32">INCIDENT</div>
                <div className="px-4 py-2 w-16">RISK</div>
                <div className="px-4 py-2 w-48">ASSET</div>
                <div className="px-4 py-2 w-32">CRIT</div>
                <div className="px-4 py-2 w-24">ALERTS</div>
                <div className="px-4 py-2 flex-1">ATT&CK</div>
                <div className="px-4 py-2 w-32">STATUS</div>
                <div className="px-4 py-2 w-32 text-right">TIME</div>
              </div>
              <div className="flex flex-col divide-y divide-border/50">
                {loading && (!incidents || incidents.length === 0) ? (
                  Array.from({ length: 15 }).map((_, i) => (
                    <div key={i} className="flex px-4 py-3"><Skeleton className="h-4 w-full" /></div>
                  ))
                ) : !incidents || incidents.length === 0 ? (
                  <div className="p-12 text-center text-muted-foreground">
                    No incidents match the current filters.
                  </div>
                ) : (
                  incidents.map((incident) => (
                    <Link 
                      key={incident.incident_id}
                      href={`/incidents/${incident.incident_id}`}
                      className="flex hover:bg-muted/30 transition-colors group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-inset"
                    >
                      <div className="px-4 py-3 w-16 flex items-center">
                        <PriorityTag priority={incident.priority} />
                      </div>
                      <div className="px-4 py-3 w-32 font-bold text-foreground flex items-center gap-1.5 truncate">
                        {incident.incident_id}
                        {incident.has_brief && <span className="text-brand text-[9px] uppercase tracking-tighter">AI</span>}
                      </div>
                      <div className="px-4 py-3 w-16 flex items-center tabular-nums">{incident.risk_score.toFixed(1)}</div>
                      <div className="px-4 py-3 w-48 text-muted-foreground truncate flex items-center" title={incident.affected_assets.join(", ")}>{incident.affected_assets[0] || "UNKNOWN"}</div>
                      <div className="px-4 py-3 w-32 uppercase tracking-wider flex items-center">{incident.asset_criticality[0] || "-"}</div>
                      <div className="px-4 py-3 w-24 text-muted-foreground flex items-center tabular-nums">{incident.alert_count}</div>
                      <div className="px-4 py-3 flex-1 text-muted-foreground truncate flex items-center" title={incident.mitre_techniques.join(" · ")}>
                        {incident.mitre_techniques.length > 0 ? incident.mitre_techniques.map(t => t.split(' - ')[0]).join(" · ") : "-"}
                      </div>
                      <div className="px-4 py-3 w-32 flex items-center">
                        <span className={incident.analyst_action ? (incident.analyst_action.toUpperCase() === "DISMISS" ? "text-muted-foreground line-through" : "text-muted-foreground") : "text-success font-bold"}>
                          {formatStatus(incident.analyst_action)}
                        </span>
                      </div>
                      <div className="px-4 py-3 w-32 text-right text-muted-foreground flex items-center justify-end tabular-nums">
                        {formatTime(incident.start_time)}
                      </div>
                    </Link>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
        
        {/* PAGINATION */}
        <div className="h-12 border-t border-border flex items-center justify-between px-4 shrink-0 bg-background font-mono text-xs">
          <div className="text-muted-foreground">
            <span className="text-foreground font-bold tabular-nums">
              {(page - 1) * limit + (incidents && incidents.length > 0 ? 1 : 0)}–{Math.min(page * limit, (page - 1) * limit + (incidents?.length || 0))}
            </span> of <span className="tabular-nums">{currentTotal}</span>
          </div>
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="sm" className="h-7 px-2 text-muted-foreground hover:text-foreground rounded-sm" onClick={() => updateFilters(priority, Math.max(1, page - 1))} disabled={page === 1 || loading}>
              <ChevronLeft className="w-3.5 h-3.5 mr-1" /> Prev
            </Button>
            <span className="w-8 text-center font-bold text-foreground tabular-nums">{page}</span>
            <Button variant="ghost" size="sm" className="h-7 px-2 text-muted-foreground hover:text-foreground rounded-sm" onClick={() => updateFilters(priority, page + 1)} disabled={!incidents || incidents.length < limit || loading}>
              Next <ChevronRight className="w-3.5 h-3.5 ml-1" />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function IncidentsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-muted-foreground font-mono text-xs">Loading queue...</div>}>
      <IncidentsQueueContent />
    </Suspense>
  );
}
