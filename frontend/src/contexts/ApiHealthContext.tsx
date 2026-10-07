"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { healthApi } from "@/lib/api/health";

export type ApiStatus = "CHECKING" | "ONLINE" | "OFFLINE";

interface ApiHealthContextType {
  status: ApiStatus;
  lastChecked: string | null;
}

const ApiHealthContext = createContext<ApiHealthContextType>({
  status: "CHECKING",
  lastChecked: null,
});

export function ApiHealthProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<ApiStatus>("CHECKING");
  const [lastChecked, setLastChecked] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    const checkHealth = async () => {
      try {
        const res = await healthApi.check();
        if (mounted) {
          setStatus(res.status === "ok" ? "ONLINE" : "OFFLINE");
          setLastChecked(new Date().toLocaleTimeString([], { hour12: false }));
        }
      } catch (err) {
        if (mounted) {
          setStatus("OFFLINE");
          setLastChecked(new Date().toLocaleTimeString([], { hour12: false }));
        }
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000);

    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <ApiHealthContext.Provider value={{ status, lastChecked }}>
      {children}
    </ApiHealthContext.Provider>
  );
}

export function useApiHealth() {
  return useContext(ApiHealthContext);
}
