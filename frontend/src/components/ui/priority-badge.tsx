"use client";

import { Badge } from "@/components/ui/badge";

export function PriorityBadge({ priority }: { priority: string }) {
  const map: Record<string, string> = {
    P1: "bg-p1/10 text-p1 border-p1/20",
    P2: "bg-p2/10 text-p2 border-p2/20",
    P3: "bg-p3/10 text-p3 border-p3/20",
    P4: "bg-p4/10 text-p4 border-p4/20",
  };
  
  return (
    <Badge variant="outline" className={`font-mono font-bold uppercase ${map[priority] || "bg-muted text-muted-foreground"}`}>
      {priority}
    </Badge>
  );
}
