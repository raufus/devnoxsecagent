import React, { useState } from "react";
import { Link, useLocation } from "wouter";
import { Activity, Shield, ListTree, PlaySquare, X, Menu, Brain, Network, Globe, GitBranch, Zap, Crosshair, Wrench, Settings, LogOut, User, Radio, GitCompare, Shuffle, History, Replace, Target, Wifi, FileText, Code } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth";

const NAV_ITEMS = [
  { path: "/dashboard", label: "OVERVIEW", icon: Activity },
  { path: "/scans/new", label: "NEW SCAN", icon: PlaySquare },
  { path: "/scans", label: "HISTORY", icon: ListTree },
];

const TOOL_ITEMS = [
  { path: "/tools/intruder", label: "INTRUDER", icon: Crosshair, color: "text-red-400" },
  { path: "/tools/interceptor", label: "INTERCEPTOR", icon: Radio, color: "text-primary" },
  { path: "/tools/repeater", label: "REPEATER", icon: Wrench, color: "text-yellow-400" },
  { path: "/tools/comparer", label: "COMPARER", icon: GitCompare, color: "text-blue-400" },
  { path: "/tools/sequencer", label: "SEQUENCER", icon: Shuffle, color: "text-purple-400" },
  { path: "/tools/http-history", label: "HTTP HISTORY", icon: History, color: "text-cyan-400" },
  { path: "/tools/match-replace", label: "MATCH & REPLACE", icon: Replace, color: "text-orange-400" },
  { path: "/tools/scope", label: "SCOPE", icon: Target, color: "text-primary" },
  { path: "/tools/websockets", label: "WEBSOCKETS", icon: Wifi, color: "text-green-400" },
  { path: "/tools/logger", label: "LOGGER", icon: FileText, color: "text-muted-foreground" },
  { path: "/tools/decoder", label: "DECODER", icon: Code, color: "text-yellow-400" },
];

function extractScanId(location: string): string | null {
  const match = location.match(/^\/scans\/([^/]+)\//);
  return match ? match[1] : null;
}

const INTEL_MODULES = [
  { key: "recon", label: "RECON_INTEL", icon: Globe, color: "text-cyan-400" },
  { key: "ai-brain", label: "AI_BRAIN", icon: Brain, color: "text-purple-400" },
  { key: "graph", label: "GRAPH_MAP", icon: Network, color: "text-orange-400" },
  { key: "exploit", label: "EXPLOIT_ENGINE", icon: Zap, color: "text-red-400" },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const { user, logout } = useAuth();
  const scanId = extractScanId(location);

  const isActive = (path: string) =>
    location === path || (path !== "/" && location.startsWith(path));

  const isIntelActive = (key: string) => location.includes(`/${key}`);

  return (
    <div className="flex h-screen w-full bg-background text-foreground overflow-hidden">
      <div className="fixed inset-0 pointer-events-none z-0 opacity-20 bg-[url('/images/cyberpunk-bg.png')] bg-cover bg-center" />
      <div className="fixed top-0 left-0 w-full h-1 bg-primary/30 z-50 animate-pulse shadow-[0_0_15px_rgba(0,255,128,0.8)]" />

      {mobileOpen && (
        <div className="fixed inset-0 bg-black/70 z-30 lg:hidden" onClick={() => setMobileOpen(false)} />
      )}

      <aside className={cn(
        "fixed inset-y-0 left-0 w-64 border-r border-primary/20 bg-background/97 backdrop-blur-md flex flex-col z-40 transition-transform duration-300",
        "lg:relative lg:translate-x-0",
        mobileOpen ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="p-5 border-b border-primary/20 flex items-center gap-3">
          <div className="w-12 h-12 shrink-0">
            <img src="/images/logo.png" alt="DevNox Logo" className="w-full h-full object-contain" />
          </div>
          <div className="flex-1">
            <h1 className="text-lg font-display font-bold text-primary tracking-wider leading-none">DEVNOX</h1>
            <h2 className="text-[10px] font-mono text-primary/70 tracking-[0.15em] uppercase">Sec_Agent v2</h2>
          </div>
          <button className="lg:hidden text-muted-foreground hover:text-primary" onClick={() => setMobileOpen(false)}>
            <X className="w-5 h-5" />
          </button>
        </div>

        <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.path);
            return (
              <Link
                key={item.path}
                href={item.path}
                onClick={() => setMobileOpen(false)}
                className={cn(
                  "flex items-center gap-3 px-4 py-3 font-mono text-sm transition-all duration-200 border-l-2",
                  active
                    ? "bg-primary/10 border-primary text-primary shadow-[inset_2px_0_10px_rgba(0,255,128,0.1)]"
                    : "border-transparent text-muted-foreground hover:bg-white/5 hover:text-foreground hover:border-primary/50"
                )}
              >
                <Icon className={cn("w-4 h-4 shrink-0", active ? "animate-pulse" : "")} />
                {item.label}
              </Link>
            );
          })}

          {/* Tools Section */}
          <div className="pt-3 pb-1 px-4">
            <div className="text-[9px] font-mono text-muted-foreground/60 uppercase tracking-[0.2em] flex items-center gap-2">
              <Wrench className="w-3 h-3" />
              TOOLS
            </div>
          </div>
          {TOOL_ITEMS.map(({ path, label, icon: Icon, color }) => {
            const active = location === path;
            return (
              <Link key={path} href={path} onClick={() => setMobileOpen(false)}
                className={cn("flex items-center gap-3 px-4 py-2.5 font-mono text-xs transition-all duration-200 border-l-2",
                  active ? `bg-primary/5 border-primary/60 ${color}` : "border-transparent text-muted-foreground hover:bg-white/5 hover:text-foreground hover:border-primary/30")}>
                <Icon className="w-3.5 h-3.5 shrink-0" />
                {label}
              </Link>
            );
          })}

          {/* Intel Modules — shown when inside a scan context */}
          {scanId && (<>
              <div className="pt-3 pb-1 px-4">
                <div className="text-[9px] font-mono text-muted-foreground/60 uppercase tracking-[0.2em] flex items-center gap-2">
                  <GitBranch className="w-3 h-3" />
                  INTEL_MODULES
                </div>
              </div>
              {INTEL_MODULES.map(({ key, label, icon: Icon, color }) => {
                const href = `/scans/${scanId}/${key}`;
                const active = isIntelActive(key);
                return (
                  <Link
                    key={key}
                    href={href}
                    onClick={() => setMobileOpen(false)}
                    className={cn(
                      "flex items-center gap-3 px-4 py-2.5 font-mono text-xs transition-all duration-200 border-l-2 ml-2",
                      active
                        ? `bg-primary/5 border-primary/60 ${color}`
                        : "border-transparent text-muted-foreground hover:bg-white/5 hover:text-foreground hover:border-primary/30"
                    )}
                  >
                    <Icon className={cn("w-3.5 h-3.5 shrink-0", active ? "animate-pulse" : "")} />
                    {label}
                  </Link>
                );
              })}

              {/* Link back to scan report */}
              <Link
                href={`/scans/${scanId}/report`}
                onClick={() => setMobileOpen(false)}
                className={cn(
                  "flex items-center gap-3 px-4 py-2.5 font-mono text-xs transition-all duration-200 border-l-2 ml-2",
                  location.includes("/report")
                    ? "bg-primary/5 border-primary/60 text-primary"
                    : "border-transparent text-muted-foreground hover:bg-white/5 hover:text-foreground hover:border-primary/30"
                )}
              >
                <Shield className="w-3.5 h-3.5 shrink-0" />
                FULL_REPORT
              </Link>
            </>
          )}
        </nav>

        <div className="p-4 border-t border-primary/20 text-xs font-mono space-y-1">
          <div className="text-primary/40 flex items-center justify-between">
            <span>SYS.STATUS: <span className="text-primary">ONLINE</span></span>
            <span className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_6px_#00ff80] animate-pulse" />
          </div>
          {user && (
            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-1.5 text-muted-foreground">
                <User className="w-3 h-3" />
                <span className="text-[10px] truncate max-w-[100px]">{user.firstName || user.email || "Admin"}</span>
                {user?.role === "admin" && (
                  <span className="text-[8px] px-1 border border-red-400/50 text-red-400">ADMIN</span>
                )}
              </div>
              <button onClick={logout} className="text-muted-foreground hover:text-red-400 transition-colors" title="Logout">
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
          {user?.role === "admin" && (
            <>
              <Link href="/admin" onClick={() => setMobileOpen(false)}
                className={cn("flex items-center gap-2 px-2 py-1.5 font-mono text-[10px] border transition-all mt-1",
                  location === "/admin" ? "border-red-400/50 text-red-400 bg-red-400/10" : "border-border/30 text-muted-foreground hover:border-red-400/30 hover:text-red-400")}>
                <Settings className="w-3 h-3" /> ADMIN_OVERVIEW
              </Link>
              {[
                { path: "/admin/users", label: "USER_MGMT" },
                { path: "/admin/scans", label: "SCAN_MGMT" },
                { path: "/admin/findings", label: "FINDINGS_DB" },
                { path: "/admin/settings", label: "SYS_SETTINGS" },
              ].map(({ path, label }) => (
                <Link key={path} href={path} onClick={() => setMobileOpen(false)}
                  className={cn("flex items-center gap-2 pl-5 py-1 font-mono text-[9px] border-l transition-all",
                    location === path ? "border-red-400/50 text-red-400" : "border-border/20 text-muted-foreground/60 hover:text-red-400/70 hover:border-red-400/20")}>
                  › {label}
                </Link>
              ))}
            </>
          )}          <div className="text-primary/25 text-[10px]">v2.0 — Autonomous Mode</div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col relative z-10 overflow-hidden min-w-0">
        <header className="lg:hidden flex items-center justify-between px-4 py-3 border-b border-primary/20 bg-background/95 backdrop-blur-md shrink-0">
          <button onClick={() => setMobileOpen(true)} className="text-primary hover:text-primary/80 transition-colors">
            <Menu className="w-6 h-6" />
          </button>
          <div className="flex items-center gap-2">
            <img src="/images/logo.png" alt="DevNox" className="w-8 h-8 object-contain" />
            <span className="font-display font-bold text-primary tracking-wider text-sm">DEVNOX_SEC_AGENT</span>
          </div>
          <Link href="/scans/new" onClick={() => setMobileOpen(false)}>
            <PlaySquare className="w-5 h-5 text-primary" />
          </Link>
        </header>

        <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(to_bottom,transparent_0%,rgba(0,255,128,0.05)_50%,transparent_100%)] h-2 animate-scanline opacity-50" />

        <main className="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8 pb-20 lg:pb-8">
          <div className="max-w-7xl mx-auto h-full">
            {children}
          </div>
        </main>

        <nav className="lg:hidden fixed bottom-0 left-0 right-0 z-40 flex items-center justify-around border-t border-primary/20 bg-background/97 backdrop-blur-md py-2 px-4">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.path);
            return (
              <Link
                key={item.path}
                href={item.path}
                className={cn(
                  "flex flex-col items-center gap-1 px-3 py-1 font-mono text-[10px] tracking-wider transition-colors",
                  active ? "text-primary" : "text-muted-foreground"
                )}
              >
                <Icon className={cn("w-5 h-5", active ? "animate-pulse" : "")} />
                {item.label.replace(" ", "_")}
              </Link>
            );
          })}
          {scanId && (
            <>
              <Link
                href={`/scans/${scanId}/recon`}
                className={cn("flex flex-col items-center gap-1 px-3 py-1 font-mono text-[10px] tracking-wider transition-colors",
                  location.includes("/recon") ? "text-cyan-400" : "text-muted-foreground")}
              >
                <Globe className="w-5 h-5" />
                RECON
              </Link>
              <Link
                href={`/scans/${scanId}/ai-brain`}
                className={cn("flex flex-col items-center gap-1 px-3 py-1 font-mono text-[10px] tracking-wider transition-colors",
                  location.includes("/ai-brain") ? "text-purple-400" : "text-muted-foreground")}
              >
                <Brain className="w-5 h-5" />
                AI
              </Link>
              <Link
                href={`/scans/${scanId}/graph`}
                className={cn("flex flex-col items-center gap-1 px-3 py-1 font-mono text-[10px] tracking-wider transition-colors",
                  location.includes("/graph") ? "text-orange-400" : "text-muted-foreground")}
              >
                <Network className="w-5 h-5" />
                GRAPH
              </Link>
              <Link
                href={`/scans/${scanId}/exploit`}
                className={cn("flex flex-col items-center gap-1 px-3 py-1 font-mono text-[10px] tracking-wider transition-colors",
                  location.includes("/exploit") ? "text-red-400" : "text-muted-foreground")}
              >
                <Zap className="w-5 h-5" />
                EXPLOIT
              </Link>
            </>
          )}
        </nav>
      </div>
    </div>
  );
}
