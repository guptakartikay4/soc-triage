import { AlertTriangle, AlertCircle, ShieldAlert, Info } from "lucide-react";

export type PriorityLevel = "P1" | "P2" | "P3" | "P4";

interface PriorityConfig {
  label: string;
  text: string;
  bg: string;
  border: string;
  icon: any;
}

export const PRIORITY_MAP: Record<PriorityLevel, PriorityConfig> = {
  P1: {
    label: "P1",
    text: "text-p1",
    bg: "bg-p1/10",
    border: "border-p1/30",
    icon: AlertTriangle,
  },
  P2: {
    label: "P2",
    text: "text-p2",
    bg: "bg-p2/10",
    border: "border-p2/30",
    icon: AlertCircle,
  },
  P3: {
    label: "P3",
    text: "text-p3",
    bg: "bg-p3/10",
    border: "border-p3/30",
    icon: ShieldAlert,
  },
  P4: {
    label: "P4",
    text: "text-p4",
    bg: "bg-p4/10",
    border: "border-p4/30",
    icon: Info,
  },
};
