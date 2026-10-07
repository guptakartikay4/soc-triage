import { PriorityLevel, PRIORITY_MAP } from "@/lib/priority";
import { cn } from "@/lib/utils";

interface PriorityTagProps {
  priority: string;
  className?: string;
  showIcon?: boolean;
}

export function PriorityTag({ priority, className, showIcon = false }: PriorityTagProps) {
  const level = (priority as PriorityLevel) || "P4";
  const config = PRIORITY_MAP[level] || PRIORITY_MAP["P4"];
  const Icon = config.icon;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm text-[11px] font-bold font-mono tracking-widest border",
        config.bg,
        config.text,
        config.border,
        className
      )}
    >
      {showIcon && <Icon className="w-3.5 h-3.5" />}
      {config.label}
    </span>
  );
}
