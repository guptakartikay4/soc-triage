"use client";

import { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import { metricsApi } from "@/lib/api/metrics";
import { useResource } from "@/lib/hooks/useResource";
import { formatDuration } from "@/lib/format";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle, Database } from "lucide-react";
import Link from "next/link";

// Dynamically import Recharts to avoid SSR hydration issues
const BarChart = dynamic(() => import("recharts").then(mod => mod.BarChart), { ssr: false });
const Bar = dynamic(() => import("recharts").then(mod => mod.Bar), { ssr: false });
const XAxis = dynamic(() => import("recharts").then(mod => mod.XAxis), { ssr: false });
const YAxis = dynamic(() => import("recharts").then(mod => mod.YAxis), { ssr: false });
const Tooltip = dynamic(() => import("recharts").then(mod => mod.Tooltip), { ssr: false });
const ResponsiveContainer = dynamic(() => import("recharts").then(mod => mod.ResponsiveContainer), { ssr: false, loading: () => <Skeleton className="w-full h-full" /> });

export default function MetricsPage() {
  const { data: metrics, error, loading, refetch } = useResource(() => metricsApi.getOverview());
  const [lastPipeline, setLastPipeline] = useState<any>(null);

  useEffect(() => {
    const localRun = localStorage.getItem("last_triage_result");
    if (localRun) {
      try {
        const parsed = JSON.parse(localRun);
        setTimeout(() => setLastPipeline(parsed), 0);
      } catch (e) {}
    }
  }, []);

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[50vh] text-center space-y-4">
        <AlertTriangle className="w-12 h-12 text-destructive" />
        <h2 className="text-lg font-semibold">{error.message || "Failed to load metrics."}</h2>
        <button onClick={() => refetch()} className="text-sm underline text-muted-foreground hover:text-foreground">Retry</button>
      </div>
    );
  }

  const reductionPercentage = metrics
    ? ((1 - metrics.total_incidents / metrics.alerts_ingested) * 100).toFixed(2)
    : "0.00";

  const priorityData = metrics ? [
    { name: "P1 Critical", count: metrics.critical_incidents, fill: "var(--color-p1)" },
    { name: "P2 High", count: metrics.high_incidents, fill: "var(--color-p2)" },
    { name: "P3 Medium", count: metrics.medium_incidents, fill: "var(--color-p3)" },
    { name: "P4 Low", count: metrics.low_incidents, fill: "var(--color-p4)" }
  ] : [];

  const stageData = lastPipeline ? [
    { name: "Ingestion", time: lastPipeline.timings.ingest },
    { name: "Correlation", time: lastPipeline.timings.correlate },
    { name: "Risk & MITRE", time: lastPipeline.timings.risk_and_mitre },
    { name: "AI Briefings", time: lastPipeline.timings.briefings }
  ] : [];

  return (
    <div className="space-y-6 animate-in fade-in duration-500 max-w-5xl mx-auto pb-12 font-sans">
      <div>
        <h1 className="text-2xl font-bold tracking-tight uppercase">System Metrics</h1>
        <p className="text-sm text-muted-foreground mt-1 font-mono uppercase tracking-widest">Performance and resolution tracking</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* WORKLOAD BAND */}
        <Panel title="Workload Transformation" className="lg:col-span-2">
          <div className="flex flex-wrap divide-x divide-border">
            <Stat label="RAW ALERTS" value={metrics?.alerts_ingested} loading={loading} />
            <Stat label="INCIDENTS" value={metrics?.total_incidents} loading={loading} />
            <Stat label="REDUCTION" value={`${reductionPercentage}%`} loading={loading} valueClass="text-success" />
            <Stat label="TRIAGED" value={`${metrics?.triaged_count || 0} / ${metrics?.total_incidents || 0}`} loading={loading} />
          </div>
        </Panel>

        {/* PRIORITY DISTRIBUTION */}
        <Panel title="Priority Distribution">
          <div className="h-[250px] w-full pt-4">
            {loading ? <Skeleton className="w-full h-full" /> : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={priorityData} layout="vertical" margin={{ top: 0, right: 30, left: 40, bottom: 0 }}>
                  <XAxis type="number" hide />
                  <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: 'var(--color-muted-foreground)', fontFamily: 'var(--font-mono)' }} width={80} />
                  <Tooltip 
                    cursor={{ fill: 'var(--color-muted)', opacity: 0.2 }}
                    contentStyle={{ backgroundColor: 'var(--color-card)', borderColor: 'var(--color-border)', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}
                    itemStyle={{ color: 'var(--color-foreground)' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={24} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Panel>

        {/* MTTT PANEL */}
        <Panel title="Mean Time To Triage (MTTT)">
          <div className="flex flex-col gap-6 pt-4 h-full">
            <div className="grid grid-cols-2 gap-4 h-full">
              <div className="bg-muted/10 border border-border rounded-sm p-4 flex flex-col justify-center text-center">
                <span className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase font-sans mb-2">Median</span>
                <span className="text-3xl font-mono font-bold tabular-nums text-foreground">
                  {loading ? <Skeleton className="h-8 w-16 mx-auto" /> : formatDuration(metrics?.median_mttt_seconds ?? null)}
                </span>
              </div>
              <div className="bg-muted/10 border border-border rounded-sm p-4 flex flex-col justify-center text-center">
                <span className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase font-sans mb-2">Mean</span>
                <span className="text-3xl font-mono font-bold tabular-nums text-foreground">
                  {loading ? <Skeleton className="h-8 w-16 mx-auto" /> : formatDuration(metrics?.average_mttt_seconds ?? null)}
                </span>
              </div>
            </div>
            <div className="bg-muted/30 border border-border rounded-sm p-3 text-[11px] font-mono text-muted-foreground">
              <span className="font-bold text-foreground">BASELINE INFO: </span>
              {loading ? "Loading..." : metrics?.mttt_baseline || "Not configured"}
            </div>
          </div>
        </Panel>

        {/* PIPELINE STAGES TIMING */}
        <Panel title="Pipeline Latency (Last Run)" className="lg:col-span-2">
          <div className="h-[200px] w-full pt-4">
            {!lastPipeline ? (
              <div className="h-full flex flex-col items-center justify-center text-muted-foreground font-mono space-y-4">
                <Database className="w-8 h-8 opacity-20" />
                <p className="text-[11px] uppercase tracking-widest">No local run data found</p>
                <Link href="/triage" className="text-brand hover:underline">Execute Pipeline</Link>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stageData} margin={{ top: 20, right: 30, left: 20, bottom: 20 }}>
                  <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: 'var(--color-muted-foreground)', fontFamily: 'var(--font-mono)' }} dy={10} />
                  <YAxis hide />
                  <Tooltip 
                    cursor={{ fill: 'var(--color-muted)', opacity: 0.2 }}
                    contentStyle={{ backgroundColor: 'var(--color-card)', borderColor: 'var(--color-border)', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}
                    formatter={(value: any) => {
                      const v = Number(value);
                      return [`${v.toFixed(3)}s`, "Latency"];
                    }}
                  />
                  <Bar dataKey="time" fill="var(--color-brand)" radius={[4, 4, 0, 0]} barSize={40} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Panel>

      </div>
    </div>
  );
}

function Panel({ title, children, className = "" }: { title: string, children: React.ReactNode, className?: string }) {
  return (
    <div className={`border border-border bg-card rounded-sm flex flex-col ${className}`}>
      <div className="px-6 py-4 border-b border-border bg-muted/10">
        <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase">{title}</h2>
      </div>
      <div className="p-6 flex-1 flex flex-col">
        {children}
      </div>
    </div>
  );
}

function Stat({ label, value, loading, valueClass = "text-foreground" }: { label: string, value: React.ReactNode, loading: boolean, valueClass?: string }) {
  return (
    <div className="flex flex-col items-center justify-center flex-1 px-4 py-2 text-center min-w-[120px]">
      <span className="text-[11px] font-bold tracking-widest text-muted-foreground mb-2 font-sans">{label}</span>
      {loading ? (
        <Skeleton className="h-8 w-16" />
      ) : (
        <span className={`text-3xl font-bold font-mono tracking-tighter tabular-nums ${valueClass}`}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </span>
      )}
    </div>
  );
}
