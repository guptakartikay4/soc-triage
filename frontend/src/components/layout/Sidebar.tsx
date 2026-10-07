"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, LayoutDashboard, ListFilter, Activity, PlayCircle, Server } from "lucide-react";
import { cn } from "@/lib/utils";
import { useApiHealth } from "@/contexts/ApiHealthContext";

const NAV_GROUPS = [
  {
    title: "COMMAND CENTER",
    items: [{ name: "Command Center", href: "/", icon: LayoutDashboard }],
  },
  {
    title: "OPERATIONS",
    items: [
      { name: "Incident Queue", href: "/incidents", icon: ListFilter },
      { name: "Triage Execution", href: "/triage", icon: PlayCircle },
    ],
  },
  {
    title: "ANALYSIS",
    items: [{ name: "System Metrics", href: "/metrics", icon: Activity }],
  },
  {
    title: "SYSTEM",
    items: [{ name: "API Status", href: "#", icon: Server }], // Point to # as per instructions "Do not add unnecessary navigation items"
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const { status, lastChecked } = useApiHealth();

  return (
    <div className="w-64 border-r border-border bg-background flex flex-col h-full font-sans transition-all">
      <div className="h-14 flex items-center px-5 border-b border-border bg-background shrink-0">
        <Shield className="w-4 h-4 text-foreground mr-3" />
        <span className="font-bold text-sm tracking-widest text-foreground">SOC TRIAGE</span>
      </div>

      <nav className="flex-1 py-6 flex flex-col gap-6 overflow-y-auto">
        {NAV_GROUPS.map((group) => (
          <div key={group.title} className="px-0">
            <h3 className="mb-2 px-5 text-[11px] font-bold tracking-[0.15em] text-muted-foreground uppercase font-sans">
              {group.title}
            </h3>
            <div className="flex flex-col gap-0.5">
              {group.items.map((item) => {
                const isActive = item.href !== "#" && (pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href)));
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    onClick={(e) => {
                       if(item.href === "#") e.preventDefault();
                    }}
                    className={cn(
                      "flex items-center gap-3 px-5 py-2 text-xs transition-colors border-l-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-inset",
                      isActive
                        ? "border-brand bg-muted/40 text-foreground font-semibold"
                        : "border-transparent text-muted-foreground hover:bg-muted/10 hover:text-foreground font-medium"
                    )}
                  >
                    <item.icon className={cn("w-4 h-4", isActive ? "text-brand" : "text-muted-foreground")} />
                    {item.name}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* BOTTOM STATUS */}
      <div className="p-4 shrink-0">
        <div className="border border-border rounded-sm p-3 bg-card font-mono text-xs flex flex-col gap-1" aria-live="polite">
          <div className="flex items-center gap-2">
            <div className={cn("w-2 h-2 rounded-full", status === "ONLINE" ? "bg-success" : status === "OFFLINE" ? "bg-destructive" : "bg-muted-foreground animate-pulse")} />
            <span className={cn("font-bold tabular-nums", status === "ONLINE" ? "text-success" : status === "OFFLINE" ? "text-destructive" : "text-muted-foreground")}>
              API {status}
            </span>
          </div>
          <div className="text-[11px] text-muted-foreground pl-4 font-sans">
            {lastChecked ? `Last checked ${lastChecked}` : "Waiting for check..."}
          </div>
        </div>
      </div>
    </div>
  );
}
