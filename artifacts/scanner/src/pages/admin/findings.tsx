import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { Layout } from "@/components/layout";
import { Bug, ShieldAlert, ExternalLink, Filter, AlertTriangle, Info, ChevronDown, ChevronUp } from "lucide-react";
import { Link } from "wouter";
import { format } from "date-fns";
import { cn } from "@/lib/utils";

interface Finding {
  id: string; scanId: string; type: string; title: string;
  severity: string; endpoint: string; method?: string;
  parameter?: string; cvssScore?: number; falsePositive: boolean;
  createdAt: string; recommendation: string; description: string;
  payload?: string; evidence?: string;
}

const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400 border-red-400/40 bg-red-400/10",
  high: "text-orange-400 border-orange-400/40 bg-orange-400/10",
  medium: "text-yellow-400 border-yellow-400/40 bg-yellow-400/10",
  low: "text-cyan-400 border-cyan-400/40 bg-cyan-400/10",
  info: "text-gray-400 border-gray-400/40 bg-gray-400/10",
};

export default function AdminFindings() {
  const { user, isAuthenticated, isLoading } = useAuth();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSev, setFilterSev] = useState("all");
  const [filterType, setFilterType] = useState("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    if (!isAuthenticated) return;
    fetch("/api/admin/findings", { credentials: "include" })
      .then(r => r.json())
      .then(d => { setFindings(d.findings || []); setLoading(false); });
  }, [isAuthenticated]);

  if (isLoading || loading) return (
    <Layout><div className="flex items-center justify-center h-64 font-mono text-sm text-muted-foreground">
      <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin mr-3" />LOADING...
    </div></Layout>
  );

  if (!isAuthenticated || user?.role !== "admin") return (
    <Layout><div className="flex flex-col items-center justify-center h-64 gap-4">
      <ShieldAlert className="w-16 h-16 text-red-500 opacity-60" />
      <p className="font-mono text-sm text-muted-foreground">ACCESS_DENIED</p>
    </div></Layout>
  );

  const types = ["all", ...Array.from(new Set(findings.map(f => f.type)))];
  const sevs = ["all", "critical", "high", "medium", "low", "info"];

  const filtered = findings.filter(f =>
    (filterSev === "all" || f.severity === filterSev) &&
    (filterType === "all" || f.type === filterType)
  );

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => { if (f.severity in counts) counts[f.severity as keyof typeof counts]++; });

  return (
    <Layout>
      <div className="space-y-5 animate-in fade-in duration-500">
        <header className="flex items-center justify-between border-b border-primary/20 pb-4">
          <div>
            <Link href="/admin" className="font-mono text-[10px] text-muted-foreground hover:text-primary transition-colors mb-1 block">← ADMIN PANEL</Link>
            <h1 className="text-2xl font-display font-bold flex items-center gap-2">
              <Bug className="w-6 h-6 text-red-400" /> FINDINGS_DATABASE
            </h1>
            <p className="text-xs font-mono text-muted-foreground mt-1">All vulnerabilities across all scans</p>
          </div>
          <div className="font-mono text-xs text-muted-foreground">{filtered.length} / {findings.length}</div>
        </header>

        {/* Severity Summary */}
        <div className="grid grid-cols-5 gap-2">
          {(["critical","high","medium","low","info"] as const).map(s => (
            <button key={s} onClick={() => setFilterSev(filterSev === s ? "all" : s)}
              className={cn("p-3 border font-mono text-center transition-all", filterSev === s ? SEV_COLOR[s] : "border-border/30 text-muted-foreground hover:border-primary/30")}>
              <div className="text-xl font-display font-bold">{counts[s]}</div>
              <div className="text-[9px] uppercase mt-0.5">{s}</div>
            </button>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2 items-center">
          <Filter className="w-3.5 h-3.5 text-muted-foreground" />
          <select value={filterType} onChange={e => setFilterType(e.target.value)}
            className="bg-black/50 border border-primary/30 px-2 py-1 font-mono text-xs text-foreground focus:outline-none focus:border-primary">
            {types.map(t => <option key={t} value={t}>{t === "all" ? "ALL TYPES" : t}</option>)}
          </select>
          <span className="font-mono text-xs text-muted-foreground">{filtered.length} results</span>
        </div>

        {/* Findings List */}
        <div className="space-y-2">
          {filtered.length === 0 ? (
            <div className="cyber-box p-8 text-center font-mono text-xs text-muted-foreground">NO_FINDINGS_MATCH_FILTER</div>
          ) : filtered.map(f => (
            <div key={f.id} className={cn("cyber-box overflow-hidden border", SEV_COLOR[f.severity])}>
              <button className="w-full text-left p-3 hover:bg-white/5 transition-colors flex items-start justify-between gap-3"
                onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                <div className="flex items-start gap-3 min-w-0 flex-1">
                  <span className={cn("px-1.5 py-0.5 border font-mono text-[9px] uppercase shrink-0 mt-0.5", SEV_COLOR[f.severity])}>
                    {f.severity}
                  </span>
                  <div className="min-w-0">
                    <div className="font-mono text-xs text-foreground font-bold truncate">{f.title}</div>
                    <div className="flex flex-wrap gap-2 mt-1">
                      <span className="font-mono text-[9px] text-muted-foreground">{f.type}</span>
                      {f.cvssScore && <span className="font-mono text-[9px] text-primary">CVSS {f.cvssScore}</span>}
                      <span className="font-mono text-[9px] text-muted-foreground truncate max-w-[200px]">{f.endpoint}</span>
                      <Link href={`/scans/${f.scanId}/report`} onClick={e => e.stopPropagation()}
                        className="font-mono text-[9px] text-cyan-400 flex items-center gap-0.5 hover:text-cyan-300">
                        <ExternalLink className="w-2.5 h-2.5" /> VIEW SCAN
                      </Link>
                    </div>
                  </div>
                </div>
                {expanded === f.id ? <ChevronUp className="w-4 h-4 text-muted-foreground shrink-0" /> : <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />}
              </button>

              {expanded === f.id && (
                <div className="border-t border-border/30 p-4 space-y-3 bg-black/20">
                  <div>
                    <div className="font-mono text-[10px] text-muted-foreground mb-1">DESCRIPTION</div>
                    <p className="font-mono text-xs text-foreground/80 leading-relaxed">{f.description}</p>
                  </div>
                  {f.payload && (
                    <div>
                      <div className="font-mono text-[10px] text-red-400 mb-1">PAYLOAD</div>
                      <pre className="bg-black/50 p-2 font-mono text-[10px] text-red-300 border border-red-400/20 overflow-x-auto">{f.payload}</pre>
                    </div>
                  )}
                  {f.evidence && (
                    <div>
                      <div className="font-mono text-[10px] text-yellow-400 mb-1">EVIDENCE</div>
                      <pre className="bg-black/50 p-2 font-mono text-[10px] text-yellow-300 border border-yellow-400/20 overflow-x-auto whitespace-pre-wrap">{f.evidence}</pre>
                    </div>
                  )}
                  <div>
                    <div className="font-mono text-[10px] text-primary mb-1">RECOMMENDATION</div>
                    <p className="font-mono text-[10px] text-foreground/70 leading-relaxed">{f.recommendation}</p>
                  </div>
                  <div className="font-mono text-[9px] text-muted-foreground">
                    Found: {format(new Date(f.createdAt), "yyyy-MM-dd HH:mm")} | Scan: {f.scanId.slice(0, 8)}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
}
