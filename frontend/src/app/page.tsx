"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { metricsApi } from "@/lib/api/metrics";
import { incidentsApi } from "@/lib/api/incidents";
import { useResource } from "@/lib/hooks/useResource";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle, ArrowRight, ArrowDown } from "lucide-react";
import { PriorityTag } from "@/components/ui/priority-tag";

export default function DashboardPage() {
  const { data: metrics, error: metricsError, loading: metricsLoading } = useResource(() => metricsApi.getOverview());
  const { data: incidentsData, error: incidentsError, loading: incidentsLoading } = useResource(() => incidentsApi.list({ limit: 10 }));

  const [lastPipelineTime, setLastPipelineTime] = useState<string | null>(null);

  useEffect(() => {
    const localRun = localStorage.getItem("last_triage_result");
    if (localRun) {
      try {
        const parsed = JSON.parse(localRun);
        if (parsed && parsed.timings && typeof parsed.timings.total_seconds === 'number') {
          setTimeout(() => setLastPipelineTime(`${parsed.timings.total_seconds.toFixed(1)}s`), 0);
        }
      } catch (e) {
        // ignore parsing errors
      }
    }
  }, []);

  const error = metricsError || incidentsError;
  const loading = metricsLoading || incidentsLoading;
  const priorityIncidents = incidentsData || [];

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[50vh] text-center space-y-4">
        <AlertTriangle className="w-12 h-12 text-destructive" />
        <h2 className="text-lg font-semibold">{error.message || "Failed to load Command Center metrics."}</h2>
        <button onClick={() => window.location.reload()} className="text-sm underline text-muted-foreground hover:text-foreground">Retry</button>
      </div>
    );
  }

  const reductionPercentage = metrics
    ? ((1 - metrics.total_incidents / metrics.alerts_ingested) * 100).toFixed(2)
    : "0.00";

  const activeCriticalIncidents = priorityIncidents.filter(
    (i) => (i.priority === "P1" || i.priority === "P2") && i.analyst_action !== "DISMISS"
  ).length;

  // Calculate Threat Overview for the visible incidents
  const mitreTally: Record<string, number> = {};
  const criticalityTally: Record<string, number> = {};
  
  priorityIncidents.forEach(inc => {
    inc.mitre_techniques.forEach(t => {
      const parent = t.split(" - ")[0]; // just tally the technique ID for density
      mitreTally[parent] = (mitreTally[parent] || 0) + 1;
    });
    inc.asset_criticality.forEach(c => {
      criticalityTally[c] = (criticalityTally[c] || 0) + 1;
    });
  });

  const topMitre = Object.entries(mitreTally).sort((a, b) => b[1] - a[1]).slice(0, 4);
  const topCriticality = Object.entries(criticalityTally).sort((a, b) => b[1] - a[1]);

  return (
    <div className="flex flex-col gap-8 animate-in fade-in duration-500 pb-12">
      {/* TOP COMMAND HEADER */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground uppercase">Command Center</h1>
        <p className="text-sm text-muted-foreground mt-1 font-medium tracking-wide">Security Operations Overview</p>
      </div>

      {/* MISSION METRICS STRIP */}
      <div className="border border-border bg-card rounded-sm flex flex-wrap divide-x divide-border overflow-hidden">
        <Stat label="ALERTS" value={metrics?.alerts_ingested} loading={loading} footnote="LIVE STATE" />
        <Stat label="INCIDENTS" value={metrics?.total_incidents} loading={loading} footnote="LIVE STATE" />
        <Stat label="REDUCTION" value={`${reductionPercentage}%`} loading={loading} valueClass="text-success" footnote="LIVE STATE" />
        <Stat label="P1" value={metrics?.critical_incidents} loading={loading} valueClass="text-p1" footnote="LIVE STATE" />
        <Stat label="P2" value={metrics?.high_incidents} loading={loading} valueClass="text-p2" footnote="LIVE STATE" />
        {lastPipelineTime ? (
          <Stat label="PIPELINE" value={lastPipelineTime} loading={false} footnote="LAST RUN · THIS BROWSER" />
        ) : (
          <Stat label="PIPELINE" value="—" loading={false} footnote={<Link href="/triage" className="hover:text-brand underline">RUN TRIAGE</Link>} />
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* LEFT COLUMN: WORKLOAD TRANSFORMATION */}
        <div className="lg:col-span-3 space-y-4">
          <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase">Workload Transformation</h2>
          <div className="border border-border bg-card rounded-sm p-6 flex flex-col items-center text-center space-y-4 font-mono">
            {loading ? <Skeleton className="h-48 w-full" /> : (
              <>
                <div className="space-y-1">
                  <div className="text-2xl font-bold text-foreground">{metrics?.alerts_ingested?.toLocaleString()}</div>
                  <div className="text-[11px] text-muted-foreground tracking-widest font-sans">RAW ALERTS</div>
                </div>
                
                <ArrowDown className="w-4 h-4 text-muted-foreground" />
                
                <div className="border border-border bg-background px-4 py-1.5 rounded-sm text-[11px] text-muted-foreground tracking-widest font-sans">
                  CORRELATION
                </div>
                
                <ArrowDown className="w-4 h-4 text-muted-foreground" />
                
                <div className="space-y-1">
                  <div className="text-2xl font-bold text-foreground">{metrics?.total_incidents?.toLocaleString()}</div>
                  <div className="text-[11px] text-muted-foreground tracking-widest font-sans">INCIDENTS</div>
                </div>

                <ArrowDown className="w-4 h-4 text-muted-foreground" />
                
                <div className="border border-border bg-background px-4 py-1.5 rounded-sm text-[11px] text-muted-foreground tracking-widest font-sans">
                  RISK ENGINE
                </div>

                <ArrowDown className="w-4 h-4 text-muted-foreground" />

                <div className="w-full grid grid-cols-2 gap-2 text-xs text-left pt-2">
                  <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-p1 font-bold">P1</span><span className="text-foreground">{metrics?.critical_incidents}</span></div>
                  <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-p2 font-bold">P2</span><span className="text-foreground">{metrics?.high_incidents}</span></div>
                  <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-p3 font-bold">P3</span><span className="text-foreground">{metrics?.medium_incidents}</span></div>
                  <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-p4 font-bold">P4</span><span className="text-foreground">{metrics?.low_incidents}</span></div>
                </div>
              </>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: QUEUE & THREAT */}
        <div className="lg:col-span-9 space-y-8">
          
          {/* THREAT OVERVIEW PANEL */}
          <div className="space-y-4">
            <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase flex justify-between">
              <span>Threat Overview</span>
              <span className="text-muted-foreground font-normal">Top N incidents by risk</span>
            </h2>
            <div className="border border-border bg-card rounded-sm p-4 grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
              {loading ? (
                <>
                  <Skeleton className="h-20 w-full" />
                  <Skeleton className="h-20 w-full" />
                </>
              ) : (
                <>
                  <div className="space-y-3">
                    <h3 className="text-[11px] font-sans font-bold tracking-widest text-muted-foreground uppercase border-b border-border pb-1">Top MITRE Techniques</h3>
                    {topMitre.length === 0 ? <div className="text-muted-foreground">No data</div> : topMitre.map(([tech, count]) => (
                      <div key={tech} className="flex justify-between items-center">
                        <span className="text-foreground">{tech}</span>
                        <span className="text-muted-foreground">{count}x</span>
                      </div>
                    ))}
                  </div>
                  <div className="space-y-3">
                    <h3 className="text-[11px] font-sans font-bold tracking-widest text-muted-foreground uppercase border-b border-border pb-1">Asset Criticality</h3>
                    {topCriticality.length === 0 ? <div className="text-muted-foreground">No data</div> : topCriticality.map(([crit, count]) => (
                      <div key={crit} className="flex justify-between items-center">
                        <span className="text-foreground uppercase">{crit}</span>
                        <span className="text-muted-foreground">{count}x</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>

          {/* CRITICAL INCIDENT QUEUE */}
          <div className="space-y-4">
            <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase flex justify-between">
              <span>Critical Incident Queue</span>
              {activeCriticalIncidents > 0 && (
                <span className="text-p1">{activeCriticalIncidents} ACTION REQUIRED (in top 10 shown)</span>
              )}
            </h2>
            <div className="border border-border bg-card rounded-sm flex flex-col divide-y divide-border">
              {loading ? (
                <div className="p-4 space-y-3">
                  {[1, 2, 3].map((i) => <Skeleton key={i} className="h-16 w-full" />)}
                </div>
              ) : priorityIncidents.length === 0 ? (
                <div className="p-8 text-center text-muted-foreground text-sm font-mono">
                  No critical incidents in queue.
                </div>
              ) : (
                priorityIncidents.slice(0, 10).map((incident) => (
                  <Link 
                    key={incident.incident_id}
                    href={`/incidents/${incident.incident_id}`}
                    className="flex items-center justify-between p-4 hover:bg-muted/30 transition-colors group relative overflow-hidden focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-inset"
                  >
                    {/* Left edge priority indicator */}
                    <div className={`absolute left-0 top-0 bottom-0 w-1 ${incident.priority === "P1" ? "bg-p1" : incident.priority === "P2" ? "bg-p2" : incident.priority === "P3" ? "bg-p3" : "bg-p4"}`} />
                    
                    <div className="pl-3 flex-1 flex flex-col gap-1.5 font-mono text-xs">
                      <div className="flex items-center gap-4 text-foreground">
                        <PriorityTag priority={incident.priority} />
                        <span className="font-bold">{incident.incident_id}</span>
                        <span className="text-muted-foreground">RISK {incident.risk_score.toFixed(1)}</span>
                      </div>
                      <div className="flex items-center gap-3 text-muted-foreground">
                        <span className="truncate max-w-[200px]">{incident.affected_assets.join(", ")}</span>
                        <span>·</span>
                        <span className="uppercase text-[11px] tracking-widest">{incident.asset_criticality[0] || "UNKNOWN"}</span>
                      </div>
                      <div className="flex items-center gap-3 text-muted-foreground">
                        <span>{incident.alert_count} alerts</span>
                        <span>·</span>
                        <span className="truncate max-w-[300px]">{incident.mitre_techniques.map(t => t.split(" - ")[0]).join(" · ")}</span>
                      </div>
                    </div>

                    <div className="flex flex-col items-end gap-3 text-xs font-mono">
                      <span className={incident.analyst_action ? "text-muted-foreground" : "text-success font-bold"}>
                        {incident.analyst_action || "NEW"}
                      </span>
                      <div className="text-muted-foreground flex items-center gap-1 group-hover:text-brand transition-colors">
                        INVESTIGATE <ArrowRight className="w-3 h-3" />
                      </div>
                    </div>
                  </Link>
                ))
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, loading, valueClass = "text-foreground", footnote }: { label: string, value: React.ReactNode, loading: boolean, valueClass?: string, footnote?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center flex-1 px-4 py-4 text-center min-w-[120px]">
      <span className="text-[11px] font-bold tracking-widest text-muted-foreground mb-1 font-sans">{label}</span>
      {loading ? (
        <Skeleton className="h-8 w-16" />
      ) : (
        <span className={`text-2xl font-bold font-mono tracking-tighter ${valueClass}`}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </span>
      )}
      {footnote && (
        <span className="text-[9px] tracking-widest text-muted-foreground/60 mt-1 uppercase font-sans">{footnote}</span>
      )}
    </div>
  );
}
