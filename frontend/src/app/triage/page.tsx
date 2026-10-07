"use client";

import { useState, useEffect } from "react";
import { triageApi } from "@/lib/api/triage";
import type { TriageRunResponse } from "@/lib/types/api";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Play, Database, Cpu, FileText, CheckCircle2, ChevronRight, Activity, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { useRouter } from "next/navigation";

export default function TriageControlPage() {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<TriageRunResponse | null>(null);
  
  // Destructive confirm dialog
  const [dialogOpen, setDialogOpen] = useState(false);
  
  // Real elapsed time
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (running) {
      interval = setInterval(() => {
        setElapsed((prev) => prev + 0.1);
      }, 100);
    } else {
      setTimeout(() => setElapsed(0), 0);
    }
    return () => clearInterval(interval);
  }, [running]);

  const triggerTriage = () => {
    setDialogOpen(true);
  };

  const handleRunTriage = async () => {
    setDialogOpen(false);
    setRunning(true);
    setResult(null);
    toast.info("Triage pipeline started. Processing synthetic alerts...");
    
    try {
      const data = await triageApi.run("dataset", true); 
      setResult(data);
      localStorage.setItem("last_triage_result", JSON.stringify(data));
      toast.success("Triage pipeline completed successfully.");
    } catch (e: any) {
      toast.error(e?.message || "Triage pipeline failed.");
      setRunning(false);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500 max-w-5xl mx-auto h-[calc(100vh-6rem)] flex flex-col font-sans">
      <div className="shrink-0 flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight uppercase">Triage Execution Control</h1>
          <p className="text-xs text-muted-foreground mt-1 font-mono uppercase tracking-widest">Execute deterministic and AI pipeline across raw alerts</p>
        </div>
        
        <Button onClick={triggerTriage} disabled={running} className="bg-brand text-brand-foreground hover:bg-brand/90 rounded-sm font-mono tracking-widest h-9 px-6 text-xs font-bold uppercase focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-brand">
          {running ? (
            <>
              <Activity className="w-3.5 h-3.5 mr-2 animate-pulse" /> Processing...
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 mr-2" /> Execute Run
            </>
          )}
        </Button>
      </div>

      <div className="flex-1 border border-border bg-card rounded-sm overflow-hidden flex flex-col">
        {/* PIPELINE VISUALIZER */}
        <div className="bg-background border-b border-border p-6 shrink-0">
          <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase mb-4">Pipeline Status</h2>
          <div className="flex items-center justify-between font-mono text-xs gap-2">
            <PipelineStage label="1. INGESTION" active={running} done={!!result} time={result?.timings?.ingest} />
            <ChevronRight className="w-4 h-4 text-muted-foreground/30 shrink-0" />
            <PipelineStage label="2. CORRELATION" active={running} done={!!result} time={result?.timings?.correlate} />
            <ChevronRight className="w-4 h-4 text-muted-foreground/30 shrink-0" />
            <PipelineStage label="3. RISK & MITRE" active={running} done={!!result} time={result?.timings?.risk_and_mitre} />
            <ChevronRight className="w-4 h-4 text-muted-foreground/30 shrink-0" />
            <PipelineStage label="4. AI BRIEFINGS" active={running} done={!!result} time={result?.timings?.briefings} />
          </div>
        </div>
        
        {/* RESULTS AREA */}
        <div className="flex-1 p-6 overflow-y-auto">
          {result && !running && (
            <div className="animate-in slide-in-from-bottom-4 duration-500 space-y-8">
              <div className="flex items-center gap-3 text-success border-b border-border/50 pb-4">
                <CheckCircle2 className="w-5 h-5" />
                <h2 className="text-sm font-bold tracking-widest uppercase">Pipeline Completed Successfully</h2>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 font-mono">
                <StatBox label="Alerts Processed" value={result.alerts_processed.toLocaleString()} />
                <StatBox label="Incidents Created" value={result.incidents_created.toLocaleString()} />
                <StatBox label="Total Runtime" value={`${result.total_seconds.toFixed(2)}s`} />
                <StatBox 
                  label="Alert Reduction" 
                  value={`${((1 - result.incidents_created / result.alerts_processed) * 100).toFixed(2)}%`} 
                  highlight 
                />
              </div>

              <div>
                <h3 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase mb-4 border-b border-border pb-1">Stage Latency Breakdown</h3>
                <div className="space-y-4">
                  <StageBar label="1. Ingestion & Normalization" time={result.timings.ingest} total={result.total_seconds} />
                  <StageBar label="2. Graph Correlation" time={result.timings.correlate} total={result.total_seconds} />
                  <StageBar label="3. Risk & MITRE Evaluation" time={result.timings.risk_and_mitre} total={result.total_seconds} />
                  <StageBar label="4. AI Incident Briefings" time={result.timings.briefings} total={result.total_seconds} />
                </div>
              </div>
              
              <div className="mt-8 pt-4 flex justify-end border-t border-border">
                 <Button onClick={() => router.push("/")} variant="outline" className="font-mono text-xs uppercase tracking-widest h-9 rounded-sm hover:text-brand focus-visible:ring-2 focus-visible:ring-brand">
                   View Command Center <ChevronRight className="w-3.5 h-3.5 ml-2" />
                 </Button>
              </div>
            </div>
          )}
          
          {!result && !running && (
            <div className="h-full flex flex-col items-center justify-center text-muted-foreground font-mono space-y-4">
              <Database className="w-12 h-12 opacity-20" />
              <p className="text-sm uppercase tracking-widest font-bold">Ready to execute triage pipeline</p>
              <p className="text-[11px] opacity-70 border border-border px-4 py-2 rounded-sm bg-muted/20">Target: 3,000 Synthetic Alerts</p>
            </div>
          )}

          {running && (
            <div className="h-full flex flex-col items-center justify-center text-brand font-mono space-y-4">
              <Activity className="w-12 h-12 animate-pulse opacity-50" />
              <p className="text-sm uppercase tracking-widest font-bold">Pipeline Running</p>
              <p className="text-2xl tabular-nums">{elapsed.toFixed(1)}s</p>
            </div>
          )}
        </div>
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-[425px] font-sans">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="w-5 h-5" /> Data Reset Warning
            </DialogTitle>
            <DialogDescription className="pt-2 text-foreground font-medium">
              Running the triage execution pipeline with <span className="font-mono text-[11px] bg-muted px-1 rounded">reset=true</span> is a destructive operation.
            </DialogDescription>
          </DialogHeader>
          <div className="py-2 text-sm text-muted-foreground space-y-2">
            <p>This action will:</p>
            <ul className="list-disc pl-5 space-y-1 text-xs">
              <li>Reset the entire database</li>
              <li>Remove all existing incidents</li>
              <li>Remove all analyst decisions and audit history</li>
              <li>Reprocess the raw synthetic benchmark alerts</li>
            </ul>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={running}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleRunTriage} disabled={running}>
              Wipe & Execute
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function PipelineStage({ label, active, done, time }: { label: string, active: boolean, done: boolean, time?: number }) {
  return (
    <div className={`flex-1 p-3 rounded-sm border ${
      done ? "border-success/30 bg-success/5 text-success" : 
      active ? "border-brand/50 bg-brand/10 text-brand shadow-[0_0_15px_rgba(var(--brand),0.1)]" : 
      "border-border bg-background text-muted-foreground opacity-50"
    } flex flex-col items-center justify-center gap-1 transition-all duration-500`}>
      <span className="font-bold tracking-wider">{label}</span>
      <span className="text-[11px] tabular-nums">
        {done && time !== undefined ? `${time.toFixed(2)}s` : active ? "Pending" : "Pending"}
      </span>
    </div>
  );
}

function StatBox({ label, value, highlight = false }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className={`p-4 rounded-sm border flex flex-col gap-1 items-start ${highlight ? 'bg-success/5 border-success/30' : 'bg-muted/10 border-border'}`}>
      <span className="text-[11px] uppercase tracking-widest text-muted-foreground font-sans">{label}</span>
      <div className={`text-2xl font-bold tracking-tight tabular-nums ${highlight ? 'text-success' : 'text-foreground'}`}>
        {value}
      </div>
    </div>
  );
}

function StageBar({ label, time, total }: { label: string, time: number, total: number }) {
  const percent = (time / total) * 100;
  return (
    <div className="space-y-1 font-mono text-xs">
      <div className="flex justify-between">
        <span className="text-muted-foreground uppercase font-sans font-bold text-[11px]">{label}</span>
        <span className="text-foreground tabular-nums">{time.toFixed(3)}s</span>
      </div>
      <div className="w-full bg-background border border-border h-2 overflow-hidden flex">
        <div className="bg-brand/50 h-full transition-all duration-1000" style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}
