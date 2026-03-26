import { useListScans } from "@workspace/api-client-react";
import { useCreateScan } from "@workspace/api-client-react";
import { Layout } from "@/components/layout";
import { Link, useLocation } from "wouter";
import { PlaySquare, Target, ShieldAlert, AlertTriangle, Bug, Shield, Activity, Globe, Brain, Network, Zap, ArrowRight, ChevronRight } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { format } from "date-fns";
import { getSeverityColor } from "@/lib/utils";
import { cn } from "@/lib/utils";
import { useState } from "react";

const ALL_MODULES = ["recon","headers","ssl","cors","xss","sqli","cmdi","lfi","xxe","ssrf","csrf","idor","redirect","auth","graphql","info"];

function QuickLaunch() {
  const [url, setUrl] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const createScan = useCreateScan();
  const [, setLocation] = useLocation();

  const launch = async () => {
    if (!url || !consent) return;
    try { new URL(url); } catch { return; }
    setLoading(true);
    try {
      const result = await createScan.mutateAsync({
        data: { targetUrl: url, scanType: "full", modules: ALL_MODULES as any, consentAcknowledged: true },
      });
      setLocation(`/scans/${result.id}/live`);
    } catch { setLoading(false); }
  };

  return (
    <div className="cyber-box p-4 border-primary/40 bg-primary/5">
      <div className="flex items-center gap-2 mb-3">
        <Zap className="w-4 h-4 text-primary" />
        <span className="font-mono text-xs text-primary font-bold">QUICK_LAUNCH — Enter URL and scan instantly</span>
      </div>
      <div className="flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1">
          <ShieldAlert className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-primary/40" />
          <input value={url} onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === "Enter" && launch()}
            className="w-full bg-black/50 border border-primary/30 pl-9 pr-4 py-2.5 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-all"
            placeholder="https://target.example.com" />
        </div>
        <button onClick={launch} disabled={loading || !url || !consent}
          className={cn("cyber-button px-6 py-2.5 text-sm flex items-center gap-2 shrink-0 transition-all",
            url && consent ? "opacity-100" : "opacity-40 cursor-not-allowed")}>
          {loading ? <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" /> : <Zap className="w-4 h-4" />}
          {loading ? "LAUNCHING..." : "LAUNCH"}
        </button>
      </div>
      <label className="flex items-center gap-2 mt-2 cursor-pointer" onClick={() => setConsent(!consent)}>
        <div className={cn("w-3.5 h-3.5 border flex items-center justify-center shrink-0 transition-all",
          consent ? "border-primary bg-primary" : "border-muted-foreground/40")}>
          {consent && <span className="text-black text-[8px] font-bold">✓</span>}
        </div>
        <span className="font-mono text-[10px] text-muted-foreground">I have authorization to scan this target</span>
      </label>
    </div>
  );
}

export default function Dashboard() {
  const { data, isLoading } = useListScans();
  const scans = data?.scans || [];

  const runningCount = scans.filter(s => s.status === "running").length;
  const completedCount = scans.filter(s => s.status === "completed").length;
  const totalFindings = scans.reduce((acc, s) => acc + s.totalFindings, 0);
  const criticalFindings = scans.reduce((acc, s) => acc + s.criticalCount, 0);

  const severityData = [
    { name: "Critical", count: scans.reduce((a, s) => a + s.criticalCount, 0), color: "#dc3232" },
    { name: "High", count: scans.reduce((a, s) => a + s.highCount, 0), color: "#ff8c00" },
    { name: "Medium", count: scans.reduce((a, s) => a + s.mediumCount, 0), color: "#e6c800" },
    { name: "Low", count: scans.reduce((a, s) => a + s.lowCount, 0), color: "#00c8dc" },
    { name: "Info", count: scans.reduce((a, s) => a + s.infoCount, 0), color: "#666" },
  ];

  const hasAnyData = severityData.some(d => d.count > 0);

  return (
    <Layout>
      <div className="space-y-6 animate-in fade-in duration-500">
        <header className="flex flex-col md:flex-row md:items-end justify-between gap-4">
          <div>
            <div className="font-mono text-[10px] text-primary/50 mb-1 tracking-widest">DEVNOX SEC AGENT v2.0</div>
            <h1 className="text-2xl sm:text-3xl">SYSTEM_OVERVIEW</h1>
            <p className="text-muted-foreground font-mono mt-1 text-xs sm:text-sm">// Autonomous vulnerability intelligence dashboard</p>
          </div>
          <Link href="/scans/new" className="cyber-button inline-flex items-center gap-2 w-fit text-sm">
            <PlaySquare className="w-4 h-4 sm:w-5 sm:h-5" />
            LAUNCH_SCAN
          </Link>
        </header>

        {/* Quick Launch */}
        <QuickLaunch />

        {/* Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
          {[
            { label: "ACTIVE_SESSIONS", value: runningCount, icon: Activity, color: "text-primary", border: "border-primary/20" },
            { label: "COMPLETED_SCANS", value: completedCount, icon: Shield, color: "text-foreground", border: "" },
            { label: "CRITICAL_THREATS", value: criticalFindings, icon: AlertTriangle, color: "text-red-500", border: "border-red-500/30" },
            { label: "TOTAL_FINDINGS", value: totalFindings, icon: Bug, color: "text-orange-500", border: "border-orange-500/30" },
          ].map(({ label, value, icon: Icon, color, border }) => (
            <div key={label} className={cn("cyber-box p-4 sm:p-5 flex flex-col gap-1 sm:gap-2", border)}>
              <div className={cn("flex items-center justify-between", color)}>
                <span className="font-mono text-[10px] sm:text-xs">{label}</span>
                <Icon className="w-4 h-4 sm:w-5 sm:h-5" />
              </div>
              <span className={cn("text-3xl sm:text-4xl font-display font-bold", color)}>{value}</span>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6">
          {/* Chart */}
          <div className="cyber-box p-4 sm:p-6 lg:col-span-2 flex flex-col h-[280px] sm:h-[350px]">
            <h3 className="font-mono text-xs sm:text-sm text-primary mb-4 flex items-center gap-2">
              <span className="w-2 h-2 bg-primary animate-pulse" />
              THREAT_DISTRIBUTION
            </h3>
            {!hasAnyData ? (
              <div className="flex-1 flex items-center justify-center text-muted-foreground font-mono text-xs text-center">
                <div>
                  <ShieldAlert className="w-10 h-10 mx-auto mb-2 opacity-20" />
                  <p>Run a scan to see threat distribution</p>
                </div>
              </div>
            ) : (
              <div className="flex-1">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                    <XAxis dataKey="name" stroke="#444" tick={{ fill: "#666", fontFamily: "JetBrains Mono", fontSize: 11 }} />
                    <YAxis stroke="#444" tick={{ fill: "#666", fontFamily: "JetBrains Mono", fontSize: 11 }} />
                    <Tooltip
                      cursor={{ fill: "rgba(0,255,128,0.08)" }}
                      contentStyle={{ backgroundColor: "#0a0a0a", border: "1px solid #00ff80", borderRadius: 0 }}
                      itemStyle={{ color: "#00ff80", fontFamily: "JetBrains Mono", fontSize: 12 }}
                    />
                    <Bar dataKey="count" radius={[2, 2, 0, 0]}>
                      {severityData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          {/* Recent Scans */}
          <div className="cyber-box p-4 sm:p-5 flex flex-col h-[280px] sm:h-[350px]">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-mono text-xs text-primary flex items-center gap-2">
                <span className="w-2 h-2 bg-primary" />
                RECENT_OPERATIONS
              </h3>
              <Link href="/scans" className="text-[10px] font-mono text-muted-foreground hover:text-primary transition-colors">
                VIEW_ALL
              </Link>
            </div>
            <div className="flex-1 overflow-y-auto space-y-2 pr-1">
              {isLoading ? (
                <div className="text-center text-muted-foreground font-mono text-xs py-8">LOADING...</div>
              ) : scans.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground font-mono text-xs gap-2">
                  <Target className="w-8 h-8 opacity-20" />
                  <span>No scans yet — launch your first scan</span>
                </div>
              ) : (
                scans.slice(0, 8).map(scan => (
                  <Link href={`/scans/${scan.id}/${scan.status === "completed" ? "report" : "live"}`} key={scan.id}>
                    <div className="p-2.5 border border-border/50 hover:border-primary/50 bg-black/20 hover:bg-primary/5 transition-all cursor-pointer group">
                      <div className="flex justify-between items-center mb-1">
                        <span className="font-mono text-[10px] text-muted-foreground group-hover:text-primary/70 transition-colors">
                          {format(new Date(scan.createdAt), "MM-dd HH:mm")}
                        </span>
                        <span className={cn("text-[9px] font-mono px-1 border uppercase tracking-wider",
                          scan.status === "running" ? "text-primary border-primary/50 bg-primary/10 animate-pulse" :
                            scan.status === "completed" ? "text-cyan-400 border-cyan-400/50" :
                              "text-muted-foreground border-border"
                        )}>
                          {scan.status}
                        </span>
                      </div>
                      <div className="text-xs font-semibold truncate text-foreground/90 group-hover:text-foreground" title={scan.targetUrl}>
                        {scan.targetUrl}
                      </div>
                      {scan.totalFindings > 0 && (
                        <div className="mt-1.5 flex gap-1.5">
                          {scan.criticalCount > 0 && <span className="font-mono text-[9px] text-red-500">{scan.criticalCount}C</span>}
                          {scan.highCount > 0 && <span className="font-mono text-[9px] text-orange-500">{scan.highCount}H</span>}
                          {scan.mediumCount > 0 && <span className="font-mono text-[9px] text-yellow-500">{scan.mediumCount}M</span>}
                          {scan.lowCount > 0 && <span className="font-mono text-[9px] text-cyan-500">{scan.lowCount}L</span>}
                        </div>
                      )}
                      {scan.status === "completed" && scan.totalFindings === 0 && (
                        <div className="mt-1"><span className="font-mono text-[9px] text-primary/50">CLEAN</span></div>
                      )}
                    </div>
                  </Link>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Intelligence Modules */}
        {(() => {
          const latestCompletedScan = scans.find(s => s.status === "completed");
          const modules = [
            {
              key: "recon",
              label: "RECON_INTEL",
              desc: "OSINT Recon Engine",
              icon: Globe,
              color: "text-cyan-400",
              border: "border-cyan-400/20",
              bg: "bg-cyan-400/5",
              glow: "hover:shadow-[0_0_20px_rgba(34,211,238,0.15)]",
              features: ["DNS/WHOIS Lookup", "Subdomain Enumeration", "Email Harvesting", "Social Footprint", "Network Mapping"],
            },
            {
              key: "ai-brain",
              label: "AI_BRAIN",
              desc: "AI Orchestrator",
              icon: Brain,
              color: "text-purple-400",
              border: "border-purple-400/20",
              bg: "bg-purple-400/5",
              glow: "hover:shadow-[0_0_20px_rgba(192,132,252,0.15)]",
              features: ["GPT-4o-mini Decisions", "Payload Generation", "Risk Correlation", "Attack Prioritization", "Vulnerability Scoring"],
            },
            {
              key: "graph",
              label: "GRAPH_MAP",
              desc: "Graph Intelligence",
              icon: Network,
              color: "text-orange-400",
              border: "border-orange-400/20",
              bg: "bg-orange-400/5",
              glow: "hover:shadow-[0_0_20px_rgba(251,146,60,0.15)]",
              features: ["Maltego-Style Visuals", "Attack Surface Map", "Node Relationships", "Domain Graph", "Interactive Topology"],
            },
            {
              key: "exploit",
              label: "EXPLOIT_ENGINE",
              desc: "Exploit Engine",
              icon: Zap,
              color: "text-red-400",
              border: "border-red-400/20",
              bg: "bg-red-400/5",
              glow: "hover:shadow-[0_0_20px_rgba(248,113,113,0.15)]",
              features: ["AI-Powered Payloads", "Exploit Chains", "Privilege Escalation", "Proof of Concept", "Risk Amplification"],
            },
          ];
          return (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="font-mono text-xs text-primary flex items-center gap-2">
                  <span className="w-2 h-2 bg-primary" />
                  INTELLIGENCE_MODULES
                </h3>
                {latestCompletedScan && (
                  <span className="font-mono text-[10px] text-muted-foreground">
                    → LINKED TO LAST SCAN
                  </span>
                )}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {modules.map(({ key, label, desc, icon: Icon, color, border, bg, glow, features }) => {
                  const href = latestCompletedScan ? `/scans/${latestCompletedScan.id}/${key}` : "/scans/new";
                  return (
                    <Link key={key} href={href}>
                      <div className={cn(
                        "cyber-box p-4 flex flex-col gap-3 cursor-pointer transition-all duration-200 h-full",
                        border, bg, glow
                      )}>
                        <div className="flex items-center justify-between">
                          <div className={cn("flex items-center gap-2", color)}>
                            <Icon className="w-4 h-4" />
                            <span className="font-mono text-[10px] font-bold tracking-wider">{label}</span>
                          </div>
                          <ChevronRight className={cn("w-3.5 h-3.5", color, "opacity-60")} />
                        </div>
                        <p className="font-mono text-[10px] text-muted-foreground">{desc}</p>
                        <div className="space-y-1 flex-1">
                          {features.map(f => (
                            <div key={f} className="flex items-center gap-1.5">
                              <span className={cn("w-1 h-1 rounded-full shrink-0", color.replace("text-", "bg-"), "opacity-60")} />
                              <span className="font-mono text-[9px] text-muted-foreground">{f}</span>
                            </div>
                          ))}
                        </div>
                        {!latestCompletedScan && (
                          <div className={cn("font-mono text-[9px] mt-1", color)}>
                            Run a scan to unlock →
                          </div>
                        )}
                      </div>
                    </Link>
                  );
                })}
              </div>
            </div>
          );
        })()}

        {/* Module Coverage */}
        <div className="cyber-box p-4 sm:p-5">
          <h3 className="font-mono text-xs text-primary mb-4 flex items-center gap-2">
            <span className="w-2 h-2 bg-primary" />
            AUTONOMOUS_SCAN_CAPABILITIES
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
            {[
              { cat: "RECON", items: ["Tech Stack", "Subdomain Enum", "Sensitive Files", "SSL/TLS", "HTTP Methods"] },
              { cat: "INJECTION", items: ["XSS Reflected", "XSS DOM-Based", "SQL Error-Based", "SQL Blind/Time", "Command Injection", "LFI/Path Traversal", "XXE Injection"] },
              { cat: "AUTH", items: ["CSRF Token Check", "CORS Misconfig", "Open Redirect", "IDOR Enum", "Rate Limit Test"] },
              { cat: "HEADERS", items: ["CSP Policy", "HSTS", "Clickjacking", "Cookie Flags", "MIME Sniffing"] },
              { cat: "INTEL", items: ["HTML Comments", "Stack Traces", "Email Harvest", "Debug Pages", "Server Banner"] },
            ].map(({ cat, items }) => (
              <div key={cat} className="space-y-1.5">
                <div className="font-mono text-[10px] text-primary border-b border-primary/20 pb-1">{cat}</div>
                {items.map(item => (
                  <div key={item} className="flex items-center gap-1.5">
                    <span className="w-1 h-1 rounded-full bg-primary/60 shrink-0" />
                    <span className="font-mono text-[9px] sm:text-[10px] text-muted-foreground">{item}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>
    </Layout>
  );
}
