"use client";

import React, { Suspense } from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { ApiHealthProvider } from "@/contexts/ApiHealthContext";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <ApiHealthProvider>
      <div className="flex h-screen overflow-hidden bg-background">
        <Suspense fallback={<div className="w-64 border-r border-border bg-card h-full" />}>
          <Sidebar />
        </Suspense>
        <div className="flex flex-col flex-1 overflow-hidden">
          <TopBar />
          <main className="flex-1 overflow-y-auto bg-muted/20 p-6">
            {children}
          </main>
        </div>
      </div>
    </ApiHealthProvider>
  );
}
