"use client";

import { useState, Suspense } from "react";
import { useParams, useRouter } from "next/navigation";
import { incidentsApi } from "@/lib/api/incidents";
import { useResource } from "@/lib/hooks/useResource";
import { formatTime, formatDateTime } from "@/lib/format";
import { PriorityTag } from "@/components/ui/priority-tag";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { ArrowLeft, AlertOctagon, Activity } from "lucide-react";
import { toast } from "sonner";

export default function IncidentDetailPage() {
  return (
    <Suspense fallback={<div className="animate-pulse space-y-4"><div className="h-10 w-full bg-muted rounded"></div></div>}>
      <IncidentDetailContent />
    </Suspense>
  );
}

function IncidentDetailContent() {
  const params = useParams();
  const router = useRouter();
  const incidentId = params.id as string;

  const { data: incident, error: incidentError, loading: incidentLoading, refetch: refetchIncident } = useResource(() => incidentsApi.getDetail(incidentId));
  const { data: decisions, refetch: refetchDecisions } = useResource(() => incidentsApi.getDecisions(incidentId));

  const [actionLoading, setActionLoading] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [actionType, setActionType] = useState<"confirm" | "escalate" | "dismiss" | null>(null);
  const [actionNote, setActionNote] = useState("");

  const openActionDialog = (type: "confirm" | "escalate" | "dismiss") => {
    setActionType(type);
    setActionNote("");
    setDialogOpen(true);
  };

  const submitAction = async () => {
    if (!actionType) return;
    setActionLoading(true);
    try {
      await incidentsApi.recordAction(incidentId, actionType, actionNote);
      toast.success(`Action recorded: ${actionType.toUpperCase()}`);
      setDialogOpen(false);
      // Strict refetch requirement to avoid drift
      await Promise.all([refetchIncident(), refetchDecisions()]);
    } catch (err: any) {
      toast.error(err?.message || `Failed to record action: ${actionType}`);
    } finally {
      setActionLoading(false);
    }
  };

  if (incidentLoading && !incident) {
    return (
      <div className="space-y-6 animate-in fade-in p-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
        <div className="grid grid-cols-2 gap-6">
          <Skeleton className="h-96" />
          <Skeleton className="h-96" />
        </div>
      </div>
    );
  }

  if (incidentError || !incident) {
    return (
      <div className="flex flex-col items-center justify-center h-[50vh] text-center space-y-4 font-sans">
        <AlertOctagon className="w-12 h-12 text-destructive" />
        <h2 className="text-lg font-semibold">{incidentError?.message || "Incident not found."}</h2>
        <Button variant="outline" onClick={() => router.push("/incidents")}>Return to Queue</Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full font-sans">
      <div className="flex-1 overflow-y-auto pb-24">
        <div className="space-y-8 animate-in fade-in">
          
          {/* HEADER */}
          <div>
            <Button variant="ghost" size="sm" className="mb-4 text-muted-foreground hover:text-foreground px-0 focus-visible:ring-2 focus-visible:ring-brand focus-visible:outline-none" onClick={() => router.back()}>
              <ArrowLeft className="w-4 h-4 mr-1" /> Back
            </Button>
            
            <div className="flex items-center gap-4">
              <h1 className="text-2xl font-bold tracking-tight uppercase font-mono">{incident.incident_id}</h1>
              <PriorityTag priority={incident.priority} />
              <span className="px-2 py-0.5 text-[11px] font-bold font-mono tracking-widest bg-muted/50 text-foreground border border-border rounded-sm">
                RISK {incident.risk_score.toFixed(1)}
              </span>
              <span className={`px-2 py-0.5 text-[11px] font-bold font-mono tracking-widest border border-border rounded-sm ${incident.analyst_action ? (incident.analyst_action.action.toUpperCase() === "DISMISS" ? "text-muted-foreground line-through" : "text-muted-foreground") : "text-success"}`}>
                STATUS: {incident.analyst_action ? incident.analyst_action.action.toUpperCase() : "NEW"}
              </span>
            </div>
          </div>

          {/* INCIDENT SUMMARY (TELEMETRY STRIP) */}
          <div className="border border-border bg-card p-4 rounded-sm flex items-center justify-between divide-x divide-border">
            <MetricItem label="START" value={formatTime(incident.start_time)} />
            <MetricItem label="END" value={formatTime(incident.end_time)} />
            <MetricItem label="ALERTS" value={incident.alert_count.toString()} />
            <MetricItem label="ASSET" value={incident.affected_assets[0] || "N/A"} />
            <MetricItem label="CRITICALITY" value={incident.asset_criticality[0]?.toUpperCase() || "N/A"} valueClass={incident.asset_criticality[0] === "critical" ? "text-p1" : ""} />
            <MetricItem label="CORRELATION" value={incident.correlation_score.toFixed(2)} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* LEFT COLUMN */}
            <div className="space-y-8">
              
              {/* RISK BREAKDOWN */}
              <div className="space-y-4">
                <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase border-b border-border pb-1 flex justify-between">
                  <span>Risk Breakdown</span>
                  <span>COMPONENT SCORE</span>
                </h2>
                <div className="bg-card border border-border rounded-sm p-4 space-y-4 font-mono text-xs">
                  <div className="flex flex-col mb-4 border-b border-border/50 pb-4 text-sm gap-2">
                    <div className="flex justify-between font-bold">
                      <span>RISK SCORE</span>
                      <span className="text-p1 tabular-nums">{incident.risk_score.toFixed(1)} / 100</span>
                    </div>
                    {incident.risk_explanation && (
                      <div className="mt-2 text-muted-foreground font-sans text-sm">
                        <span className="font-bold text-foreground text-[11px] uppercase tracking-widest block mb-1">Why this incident ranked high</span>
                        {incident.risk_explanation}
                      </div>
                    )}
                  </div>
                  <RiskRow label="Asset Criticality" score={incident.asset_criticality_score} />
                  <RiskRow label="Severity" score={incident.severity_score} />
                  <RiskRow label="MITRE Risk" score={incident.attack_context_score} />
                  <RiskRow label="Correlation" score={incident.correlation_strength_score} />
                  <RiskRow label="Evidence" score={incident.evidence_strength_score} />
                </div>
              </div>

              {/* CORRELATION EVIDENCE */}
              <div className="space-y-4">
                <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase border-b border-border pb-1 flex justify-between">
                  <span>Correlation Logic</span>
                  <span className="text-muted-foreground font-normal">Cross-alert mapping</span>
                </h2>
                <div className="bg-card border border-border rounded-sm p-4 text-xs font-mono max-h-96 overflow-y-auto">
                  {(!incident.correlation_evidence || incident.correlation_evidence.length === 0) ? (
                    <span className="text-muted-foreground">No cross-alert correlation evidence.</span>
                  ) : (
                    <div className="space-y-6">
                      {incident.correlation_evidence.slice(0, 5).map((edge, idx) => (
                        <div key={idx} className="flex flex-col text-muted-foreground">
                          <div className="font-bold text-foreground">ALERT {edge.alert_a.slice(-5)}</div>
                          <div className="pl-4 py-1 flex flex-col border-l border-border ml-2 my-1 relative">
                            {edge.signals.map((signal, sIdx) => {
                              const friendlySignal = signal.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase());
                              return (
                                <div key={sIdx} className="flex items-center">
                                  <span className="text-border mr-2">├──</span>
                                  <span className="text-muted-foreground">Same {friendlySignal}</span>
                                </div>
                              );
                            })}
                            <div className="absolute -bottom-2 -left-[5px] text-border text-[8px]">▼</div>
                          </div>
                          <div className="font-bold text-foreground mt-2">ALERT {edge.alert_b.slice(-5)}</div>
                        </div>
                      ))}
                      {incident.correlation_evidence.length > 5 && (
                        <div className="text-muted-foreground pt-2 border-t border-border/50 text-center">
                          + {incident.correlation_evidence.length - 5} more edges
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* MITRE ATT&CK */}
              <div className="space-y-4">
                <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase border-b border-border pb-1">MITRE ATT&CK</h2>
                <div className="bg-card border border-border rounded-sm p-4 font-mono text-xs flex flex-col gap-6">
                  {(!incident.mitre_context?.tactics_roll_up || incident.mitre_context.tactics_roll_up.length === 0) ? (
                    <span className="text-muted-foreground">No tactic roll-up available</span>
                  ) : (
                    <div>
                      <h4 className="text-[11px] text-muted-foreground mb-2">TACTICS:</h4>
                      <div className="flex flex-wrap gap-2">
                        {incident.mitre_context.tactics_roll_up.map(t => (
                          <span key={t} className="px-2 py-1 bg-background border border-border rounded-sm">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {(!incident.mitre_context?.techniques || incident.mitre_context.techniques.length === 0) ? (
                    <span className="text-muted-foreground">No techniques mapped.</span>
                  ) : (
                    <div>
                      <h4 className="text-[11px] text-muted-foreground mb-2">TECHNIQUES:</h4>
                      <div className="space-y-6">
                        {incident.mitre_context.techniques.map(t => (
                          <div key={t.technique_id} className="flex flex-col gap-1 border-l-2 border-brand/40 pl-3">
                            <div className="flex items-baseline gap-3">
                              <span className="text-foreground font-bold">{t.technique_id}</span>
                              <span className="text-foreground">{t.name}</span>
                            </div>
                            <div className="grid grid-cols-[60px_1fr] gap-2 mt-2">
                              <span className="text-muted-foreground text-[11px] tracking-widest">TACTIC</span>
                              <span className="text-muted-foreground">{t.tactic}</span>
                              
                              <span className="text-muted-foreground text-[11px] tracking-widest">WHY</span>
                              <span className="text-muted-foreground">{t.reason}</span>
                              
                              <span className="text-muted-foreground text-[11px] tracking-widest">SOURCE</span>
                              <span className="text-muted-foreground">{t.source}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* RIGHT COLUMN */}
            <div className="space-y-8">
              
              {/* AI INCIDENT BRIEF */}
              <div className="space-y-4">
                <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase border-b border-border pb-1 flex justify-between items-center">
                  <span>AI Incident Brief</span>
                  <span className="text-[10px] tracking-widest text-brand">AI-ASSISTED · HUMAN VERIFIED</span>
                </h2>
                <div className="bg-background border border-brand/30 rounded-sm p-4 font-mono text-xs">
                  {!incident.brief ? (
                    <span className="text-muted-foreground">No AI intelligence generated.</span>
                  ) : (
                    <div className="space-y-6">
                      <div className="flex items-center justify-between border-b border-border/50 pb-3">
                        <div className="flex flex-col gap-1">
                          <span className="text-[11px] tracking-widest text-muted-foreground uppercase">Source</span>
                          <span className="text-foreground font-bold" title={incident.brief.generation_source}>
                            {incident.brief.generation_source === "deterministic_fallback" ? "Deterministic Fallback Logic" : incident.brief.generation_source}
                          </span>
                        </div>
                        {incident.brief.is_fallback && (
                          <span className="px-2 py-1 bg-muted text-muted-foreground text-[11px] font-bold tracking-widest border border-border rounded-sm">
                            DETERMINISTIC FALLBACK
                          </span>
                        )}
                      </div>
                      <div>
                        <h4 className="text-foreground font-bold mb-2">EXECUTIVE SUMMARY</h4>
                        <p className="text-muted-foreground leading-relaxed font-sans text-sm">{incident.brief.summary}</p>
                      </div>
                      <div>
                        <h4 className="text-foreground font-bold mb-2">KEY EVIDENCE</h4>
                        <ul className="text-muted-foreground space-y-1">
                          {(incident.brief.key_evidence || []).map((e, i) => <li key={i}>- {e}</li>)}
                        </ul>
                      </div>
                      <div>
                        <h4 className="text-foreground font-bold mb-2">AFFECTED ASSETS & IMPACT</h4>
                        <p className="text-muted-foreground leading-relaxed font-sans text-sm">{incident.brief.why_it_matters}</p>
                      </div>
                      <div>
                        <h4 className="text-foreground font-bold mb-2">ANALYST FOCUS</h4>
                        <ul className="text-muted-foreground space-y-1">
                          {(incident.brief.recommended_next_steps || []).map((s, i) => <li key={i}>- {s}</li>)}
                        </ul>
                      </div>
                      <div>
                        <h4 className="text-foreground font-bold mb-2">CONFIDENCE</h4>
                        <span className="text-muted-foreground">{incident.brief.confidence}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* ATTACK TIMELINE */}
              <div className="space-y-4">
                <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase border-b border-border pb-1">Attack Timeline</h2>
                <div className="bg-card border border-border rounded-sm p-4 font-mono text-xs max-h-[400px] overflow-y-auto">
                  <div className="relative border-l border-border ml-3 space-y-6 pb-4">
                    {incident.timeline.map((alert, idx) => (
                      <div key={idx} className="relative pl-6">
                        <div className={`absolute -left-1.5 top-1.5 w-3 h-3 rounded-full border-2 bg-background ${alert.severity === 'high' ? 'border-p2' : alert.severity === 'critical' ? 'border-p1' : 'border-p4'}`} />
                        <div className="flex flex-col gap-1 text-muted-foreground">
                          <span className="font-bold text-foreground">{formatTime(alert.timestamp)}</span>
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.5 bg-muted text-[10px] rounded-sm text-foreground">{alert.alert_type}</span>
                          </div>
                          {alert.mitre_technique && (
                            <span className="text-muted-foreground">{alert.mitre_technique}</span>
                          )}
                          {!alert.mitre_technique && alert.description && (
                            <span className="text-muted-foreground truncate max-w-[300px]" title={alert.description}>{alert.description}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* DECISION HISTORY */}
              <div className="space-y-4">
                <h2 className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase border-b border-border pb-1">Analyst Audit Trail</h2>
                <div className="bg-card border border-border rounded-sm p-4 font-mono text-xs">
                  {!decisions || decisions.length === 0 ? (
                    <span className="text-muted-foreground">No analyst decisions yet.</span>
                  ) : (
                    <div className="space-y-4">
                      {decisions.map((d, i) => (
                        <div key={i} className="flex flex-col gap-1 border-l-2 border-border pl-3">
                          <div className="flex items-center gap-2">
                            <span className="text-foreground font-bold">{d.decision.toUpperCase()}</span>
                            <span className="text-muted-foreground">by</span>
                            <span className="text-foreground">{d.username}</span>
                            <span className="text-muted-foreground text-[10px] ml-auto">{formatDateTime(d.created_at)}</span>
                          </div>
                          {d.notes && <div className="text-muted-foreground italic mt-1 font-sans text-sm">&quot;{d.notes}&quot;</div>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

            </div>
          </div>
        </div>
      </div>

      {/* BOTTOM ACTION BAR - properly sticky in the container */}
      <div className="sticky bottom-0 left-0 right-0 h-16 border-t border-border bg-card flex items-center justify-between px-8 shadow-[0_-4px_12px_rgba(0,0,0,0.5)] z-20">
        <span className="text-[11px] font-bold tracking-widest text-muted-foreground uppercase font-sans">Analyst Decision</span>
        <div className="flex items-center gap-4 font-mono text-xs">
          <Button variant="outline" className="border-success/50 text-success hover:bg-success/10 rounded-none px-6 h-9 focus-visible:ring-2 focus-visible:ring-success" onClick={() => openActionDialog("confirm")} disabled={actionLoading}>
            ✓ CONFIRM
          </Button>
          <Button variant="outline" className="border-p2/50 text-p2 hover:bg-p2/10 rounded-none px-6 h-9 focus-visible:ring-2 focus-visible:ring-p2" onClick={() => openActionDialog("escalate")} disabled={actionLoading}>
            ↑ ESCALATE
          </Button>
          <Button variant="outline" className="border-muted-foreground/50 text-muted-foreground hover:bg-muted rounded-none px-6 h-9 focus-visible:ring-2 focus-visible:ring-muted-foreground" onClick={() => openActionDialog("dismiss")} disabled={actionLoading}>
            × DISMISS
          </Button>
        </div>
      </div>

      {/* ACTION CONFIRMATION DIALOG */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-[425px] font-sans">
          <DialogHeader>
            <DialogTitle>Confirm Action</DialogTitle>
            <DialogDescription>
              You are about to <strong className="uppercase">{actionType}</strong> incident <strong className="text-foreground">{incident.incident_id}</strong>.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Textarea
              placeholder="Optional analyst notes or justification..."
              value={actionNote}
              onChange={(e) => setActionNote(e.target.value)}
              className="resize-none font-sans"
              rows={4}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={actionLoading}>
              Cancel
            </Button>
            <Button onClick={submitAction} disabled={actionLoading}>
              {actionLoading ? "Submitting..." : "Confirm Action"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function MetricItem({ label, value, valueClass = "text-foreground" }: { label: string, value: string, valueClass?: string }) {
  return (
    <div className="flex flex-col items-center justify-center flex-1 px-4 text-center min-w-[90px]">
      <span className="text-[11px] font-bold tracking-widest text-muted-foreground mb-1 font-sans">{label}</span>
      <span className={`text-xl font-bold font-mono tracking-tighter tabular-nums ${valueClass}`}>
        {value}
      </span>
    </div>
  );
}

function RiskRow({ label, score }: { label: string, score: number }) {
  const blocks = Math.ceil((score / 100) * 20); // 20 blocks max
  return (
    <div className="flex items-center justify-between">
      <span className="w-36 text-muted-foreground">{label}</span>
      <span className="flex-1 text-p1 tracking-[2px]">
        {"█".repeat(blocks)}
      </span>
      <span className="w-12 text-right tabular-nums">+{score.toFixed(1)}</span>
    </div>
  );
}
