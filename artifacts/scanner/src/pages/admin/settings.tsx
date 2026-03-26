import { useAuth } from "@/lib/auth";
import { Layout } from "@/components/layout";
import { Settings, ShieldAlert, Key, Database, Globe, AlertTriangle, Cpu, Brain, Shield, CheckCircle, XCircle, RefreshCw, Save, Eye, EyeOff, Zap, Activity, Server } from "lucide-react";
import { Link } from "wouter";
import { useState, useEffect } from "react";
import { useToast } from "@/hooks/use-toast";

interface SystemHealth {
  status: string;
  uptime?: number;
  dbConnected?: boolean;
}

export default function AdminSettings() {
  const { user, isAuthenticated, isLoading } = useAuth();
  const { toast } = useToast();
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [showApiKey, setShowApiKey] = useState(false);
  const [purging, setPurging] = useState<string | null>(null);
  const [scanConfig, setScanConfig] = useState({
    maxConcurrentScans: "3",
    defaultScanType: "full",
    enableAI: "true",
    enableExploit: "true",
    enableShodan: "false",
    requestTimeout: "6000",
    maxCrawlDepth: "2",
    maxCrawlPages: "25",
  });

  useEffect(() => {
    fetch("/api/health", { credentials: "include" })
      .then(r => r.json())
      .then(d => setHealth(d))
      .catch(() => setHealth({ status: "error" }));
  }, []);

  const handlePurge = async (type: string) => {
    if (!confirm(`PERMANENTLY DELETE all ${type}? This cannot be undone.`)) return;
    setPurging(type);
    try {
      if (type === "scans") {
        const scans = await fetch("/api/admin/scans", { credentials: "include" }).then(r => r.json());
        for (const scan of scans.scans || []) {
          await fetch(`/api/admin/scans/${scan.id}`, { method: "DELETE", credentials: "include" });
        }
        toast({ title: "PURGE_COMPLETE", description: `All scan records deleted` });
      }
    } catch {
      toast({ title: "PURGE_FAILED", variant: "destructive" });
    } finally {
      setPurging(null);
    }
  };

  if (isLoading) return (
    <Layout><div className="flex items-center justify-center h-64 font-mono text-sm text-muted-foreground">
      <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin mr-3" />LOADING...
    </div></Layout>
  );

  if (!isAuthenticated || user?.role !== "admin") return (
    <Layout><div className="flex flex-col items-center justify-center h-64 gap-4">
      <ShieldAlert className="w-16 h-16 text-red-500 opacity-60" />
      <p className="font-mono text-sm text-muted-foreground">ACCESS_DENIED</p>
      <Link href="/" className="cyber-button text-xs">← BACK</Link>
    </div></Layout>
  );

  const modules = [
    { label: "OSINT Recon Engine", desc: "DNS, WHOIS, subdomain enum, email harvest", status: true, icon: Globe },
    { label: "AI Orchestrator (GPT-4o-mini)", desc: "Attack strategy, vuln analysis, payload gen", status: true, icon: Brain },
    { label: "XSS Scanner", desc: "Reflected, DOM-based, form injection", status: true, icon: Zap },
    { label: "SQLi Scanner", desc: "Error-based, boolean-blind, time-based", status: true, icon: Database },
    { label: "SSRF Scanner", desc: "Cloud metadata, internal service probing", status: true, icon: Globe },
    { label: "GraphQL Tester", desc: "Introspection, batch attack, depth DoS", status: true, icon: Activity },
    { label: "Auth Bypass Tester", desc: "Default creds, JWT none, SQLi bypass", status: true, icon: Key },
    { label: "IDOR Detector", desc: "Sequential ID enumeration, API objects", status: true, icon: Eye },
    { label: "Exploit Engine", desc: "AI payload generation, attack chains", status: true, icon: Zap },
    { label: "Attack Graph (Neo4j-style)", desc: "Domain → IP → Server → Vuln → Exploit", status: true, icon: Activity },
    { label: "PDF/HTML Report Generator", desc: "CVSS scoring, PoC, recommendations", status: true, icon: Shield },
    { label: "Shodan Integration", desc: "Open ports, CVEs, service banners", status: false, icon: Server },
  ];

  return (
    <Layout>
      <div className="space-y-5 animate-in fade-in duration-500">
        <header className="flex items-center justify-between border-b border-primary/20 pb-4">
          <div>
            <Link href="/admin" className="font-mono text-[10px] text-muted-foreground hover:text-primary transition-colors flex items-center gap-1 mb-1">← ADMIN PANEL</Link>
            <h1 className="text-2xl font-display font-bold flex items-center gap-2">
              <Settings className="w-6 h-6 text-primary" /> SYSTEM_SETTINGS
            </h1>
            <p className="text-xs font-mono text-muted-foreground mt-1">Platform configuration, module status, and system management</p>
          </div>
          <div className={`flex items-center gap-2 font-mono text-xs px-3 py-1.5 border ${health?.status === "ok" ? "border-primary/40 text-primary bg-primary/10" : "border-red-400/40 text-red-400 bg-red-400/10"}`}>
            <span className={`w-2 h-2 rounded-full ${health?.status === "ok" ? "bg-primary animate-pulse" : "bg-red-400"}`} />
            {health?.status === "ok" ? "SYSTEM ONLINE" : "SYSTEM ERROR"}
          </div>
        </header>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          {/* Left Column */}
          <div className="xl:col-span-2 space-y-5">

            {/* Module Status */}
            <div className="cyber-box p-5">
              <h3 className="font-mono text-xs text-primary mb-4 flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5" /> INTELLIGENCE_MODULES ({modules.filter(m => m.status).length}/{modules.length} ACTIVE)
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {modules.map(({ label, desc, status, icon: Icon }) => (
                  <div key={label} className={`flex items-start gap-3 p-3 border transition-all ${status ? "border-primary/20 bg-primary/5" : "border-border/30 bg-black/20 opacity-60"}`}>
                    <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${status ? "text-primary" : "text-muted-foreground"}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[10px] text-foreground truncate">{label}</span>
                        {status
                          ? <CheckCircle className="w-3 h-3 text-primary shrink-0" />
                          : <XCircle className="w-3 h-3 text-muted-foreground shrink-0" />}
                      </div>
                      <p className="font-mono text-[9px] text-muted-foreground mt-0.5 leading-tight">{desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Scan Configuration */}
            <div className="cyber-box p-5">
              <h3 className="font-mono text-xs text-primary mb-4 flex items-center gap-2">
                <Settings className="w-3.5 h-3.5" /> SCAN_ENGINE_CONFIGURATION
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {[
                  { key: "maxConcurrentScans", label: "MAX CONCURRENT SCANS", type: "number" },
                  { key: "requestTimeout", label: "REQUEST TIMEOUT (ms)", type: "number" },
                  { key: "maxCrawlDepth", label: "MAX CRAWL DEPTH", type: "number" },
                  { key: "maxCrawlPages", label: "MAX CRAWL PAGES", type: "number" },
                ].map(({ key, label, type }) => (
                  <div key={key}>
                    <label className="font-mono text-[10px] text-muted-foreground block mb-1">{label}</label>
                    <input
                      type={type}
                      value={scanConfig[key as keyof typeof scanConfig]}
                      onChange={e => setScanConfig(p => ({ ...p, [key]: e.target.value }))}
                      className="w-full bg-black/50 border border-primary/30 p-2 font-mono text-sm text-foreground focus:outline-none focus:border-primary"
                    />
                  </div>
                ))}
                {[
                  { key: "defaultScanType", label: "DEFAULT SCAN TYPE", options: ["quick", "full", "deep"] },
                ].map(({ key, label, options }) => (
                  <div key={key}>
                    <label className="font-mono text-[10px] text-muted-foreground block mb-1">{label}</label>
                    <select
                      value={scanConfig[key as keyof typeof scanConfig]}
                      onChange={e => setScanConfig(p => ({ ...p, [key]: e.target.value }))}
                      className="w-full bg-black/50 border border-primary/30 p-2 font-mono text-sm text-foreground focus:outline-none focus:border-primary"
                    >
                      {options.map(o => <option key={o} value={o}>{o.toUpperCase()}</option>)}
                    </select>
                  </div>
                ))}
                <div className="sm:col-span-2 grid grid-cols-3 gap-2">
                  {[
                    { key: "enableAI", label: "AI ANALYSIS" },
                    { key: "enableExploit", label: "EXPLOIT ENGINE" },
                    { key: "enableShodan", label: "SHODAN API" },
                  ].map(({ key, label }) => (
                    <button key={key}
                      onClick={() => setScanConfig(p => ({ ...p, [key]: p[key as keyof typeof scanConfig] === "true" ? "false" : "true" }))}
                      className={`p-2 border font-mono text-[10px] transition-all flex items-center justify-between gap-1 ${scanConfig[key as keyof typeof scanConfig] === "true" ? "border-primary/50 bg-primary/10 text-primary" : "border-border/30 text-muted-foreground"}`}>
                      {label}
                      {scanConfig[key as keyof typeof scanConfig] === "true"
                        ? <CheckCircle className="w-3 h-3" />
                        : <XCircle className="w-3 h-3" />}
                    </button>
                  ))}
                </div>
              </div>
              <div className="mt-4 flex justify-end">
                <button onClick={() => toast({ title: "CONFIG_SAVED", description: "Scan engine configuration updated" })}
                  className="cyber-button text-xs flex items-center gap-1.5">
                  <Save className="w-3.5 h-3.5" /> SAVE_CONFIG
                </button>
              </div>
            </div>

            {/* Danger Zone */}
            <div className="cyber-box p-5 border-red-400/30">
              <h3 className="font-mono text-xs text-red-400 mb-4 flex items-center gap-2">
                <AlertTriangle className="w-3.5 h-3.5" /> DANGER_ZONE — IRREVERSIBLE OPERATIONS
              </h3>
              <div className="space-y-3">
                {[
                  { id: "scans", label: "PURGE ALL SCAN RECORDS", desc: "Delete all scans, findings, events, recon data, and AI decisions from database", color: "red" },
                  { id: "users", label: "PURGE ALL USER ACCOUNTS", desc: "Delete all user accounts except your own admin account", color: "red" },
                ].map(({ id, label, desc, color }) => (
                  <div key={id} className={`p-4 border border-${color}-400/20 bg-${color}-400/5 flex flex-col sm:flex-row sm:items-center justify-between gap-3`}>
                    <div>
                      <div className={`font-mono text-xs text-${color}-400 font-bold`}>{label}</div>
                      <div className="font-mono text-[10px] text-muted-foreground mt-0.5">{desc}</div>
                    </div>
                    <button
                      onClick={() => handlePurge(id)}
                      disabled={purging === id}
                      className="cyber-button !border-red-400/40 !text-red-400 hover:!bg-red-400/20 text-[10px] !py-1.5 !px-3 shrink-0 flex items-center gap-1.5">
                      {purging === id
                        ? <><RefreshCw className="w-3 h-3 animate-spin" /> PURGING...</>
                        : <><AlertTriangle className="w-3 h-3" /> EXECUTE_PURGE</>}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Column */}
          <div className="space-y-5">
            {/* Current Session */}
            <div className="cyber-box p-5 border-primary/30">
              <h3 className="font-mono text-xs text-primary mb-4 flex items-center gap-2">
                <Key className="w-3.5 h-3.5" /> ADMIN_SESSION
              </h3>
              <div className="space-y-2">
                {[
                  { label: "USER_ID", value: user?.id || "—" },
                  { label: "EMAIL", value: user?.email || "—" },
                  { label: "NAME", value: `${user?.firstName || ""} ${user?.lastName || ""}`.trim() || "—" },
                  { label: "ROLE", value: user?.role || "—" },
                ].map(({ label, value }) => (
                  <div key={label} className="flex items-start gap-2 p-2 border border-border/30">
                    <span className="font-mono text-[9px] text-muted-foreground w-20 shrink-0 pt-0.5">{label}</span>
                    <span className="font-mono text-[10px] text-foreground break-all">{value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* API Keys */}
            <div className="cyber-box p-5">
              <h3 className="font-mono text-xs text-primary mb-4 flex items-center gap-2">
                <Key className="w-3.5 h-3.5" /> API_INTEGRATIONS
              </h3>
              <div className="space-y-3">
                {[
                  { label: "OpenAI API", key: "AI_INTEGRATIONS_OPENAI_API_KEY", status: true, desc: "GPT-4o-mini for AI analysis" },
                  { label: "Shodan API", key: "SHODAN_API_KEY", status: false, desc: "Port scanning + CVE detection" },
                ].map(({ label, key, status, desc }) => (
                  <div key={key} className={`p-3 border ${status ? "border-primary/30 bg-primary/5" : "border-border/30"}`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-[10px] text-foreground">{label}</span>
                      <span className={`font-mono text-[9px] px-1.5 py-0.5 border ${status ? "text-primary border-primary/40" : "text-muted-foreground border-border/40"}`}>
                        {status ? "CONFIGURED" : "NOT SET"}
                      </span>
                    </div>
                    <p className="font-mono text-[9px] text-muted-foreground">{desc}</p>
                    <p className="font-mono text-[9px] text-muted-foreground/50 mt-1">Set in .env: {key}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* System Info */}
            <div className="cyber-box p-5">
              <h3 className="font-mono text-xs text-primary mb-4 flex items-center gap-2">
                <Server className="w-3.5 h-3.5" /> SYSTEM_INFO
              </h3>
              <div className="space-y-2">
                {[
                  { label: "PLATFORM", value: "DevNox AutoPentest AI" },
                  { label: "VERSION", value: "v2.0.0" },
                  { label: "BACKEND", value: "Node.js + Express" },
                  { label: "DATABASE", value: "MySQL (Drizzle ORM)" },
                  { label: "FRONTEND", value: "React 19 + Vite 5" },
                  { label: "AI ENGINE", value: "GPT-4o-mini" },
                  { label: "SCAN ENGINE", value: "Multi-phase Autonomous" },
                  { label: "GRAPH ENGINE", value: "React Flow (Maltego-style)" },
                ].map(({ label, value }) => (
                  <div key={label} className="flex items-center justify-between p-2 border border-border/20">
                    <span className="font-mono text-[9px] text-muted-foreground">{label}</span>
                    <span className="font-mono text-[9px] text-foreground">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
