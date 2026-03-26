import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { Layout } from "@/components/layout";
import { ShieldAlert, Trash2, ExternalLink, Globe, Brain, Network, Zap, FileText, Cpu } from "lucide-react";
import { Link } from "wouter";
import { format } from "date-fns";
import { useToast } from "@/hooks/use-toast";

interface Scan {
  id: string;
  targetUrl: string;
  scanType: string;
  status: string;
  currentPhase: string;
  progress: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  createdAt: string;
}

export default function AdminScans() {
  const { user, isAuthenticated, isLoading } = useAuth();
  const { toast } = useToast();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = () => {
    fetch("/api/admin/scans", { credentials: "include" })
      .then(r => r.json())
      .then(d => { setScans(d.scans || []); setLoading(false); });
  };

  useEffect(() => { if (isAuthenticated) fetchScans(); }, [isAuthenticated]);

  const handleDelete = async (scanId: string, url: string) => {
    if (!confirm(`DELETE SCAN for ${url}?`)) return;
    const res = await fetch(`/api/admin/scans/${scanId}`, { method: "DELETE", credentials: "include" });
    if (res.ok) { fetchScans(); toast({ title: "SCAN_DELETED", description: url }); }
    else toast({ title: "ERROR", description: "Failed to delete scan", variant: "destructive" });
  };

  if (isLoading || loading) return (
    <Layout><div className="flex items-center justify-center h-64 font-mono text-sm text-muted-foreground">
      <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin mr-3" />LOADING...
    </div></Layout>
  );

  const userRole = (user as any)?.role;
  if (!isAuthenticated || userRole !== "admin") return (
    <Layout><div className="flex flex-col items-center justify-center h-64 gap-4">
      <ShieldAlert className="w-16 h-16 text-red-500 opacity-60" />
      <p className="font-mono text-sm text-muted-foreground">ACCESS_DENIED</p>
      <Link href="/" className="cyber-button text-xs">← BACK</Link>
    </div></Layout>
  );

  const statusColor: Record<string, string> = {
    completed: "text-cyan-400 border-cyan-400/50",
    running: "text-primary border-primary/50 animate-pulse",
    failed: "text-red-500 border-red-500/50",
    cancelled: "text-gray-400 border-gray-400/50",
  };

  return (
    <Layout>
      <div className="space-y-6 animate-in fade-in duration-500">
        <header className="flex items-center justify-between">
          <div>
            <Link href="/admin" className="font-mono text-[10px] text-muted-foreground hover:text-primary transition-colors flex items-center gap-1 mb-1">← ADMIN PANEL</Link>
            <h1 className="text-2xl sm:text-3xl flex items-center gap-3">
              <ShieldAlert className="w-7 h-7 text-orange-400 shrink-0" />
              SCAN_MANAGEMENT
            </h1>
            <p className="text-muted-foreground font-mono mt-1 text-xs">// View and manage all scan operations across all users</p>
          </div>
          <div className="font-mono text-xs text-muted-foreground">{scans.length} SCANS</div>
        </header>

        <div className="cyber-box overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full font-mono text-sm">
              <thead>
                <tr className="border-b border-primary/30 bg-black/50 text-primary/70">
                  <th className="p-4 font-normal text-left">TARGET</th>
                  <th className="p-4 font-normal text-left">DATE</th>
                  <th className="p-4 font-normal text-left">TYPE</th>
                  <th className="p-4 font-normal text-left">STATUS</th>
                  <th className="p-4 font-normal text-center">C/H/M/L</th>
                  <th className="p-4 font-normal text-left">INTEL</th>
                  <th className="p-4 font-normal text-right">ACTIONS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {scans.map(scan => (
                  <tr key={scan.id} className="hover:bg-primary/5 transition-colors">
                    <td className="p-4">
                      <div className="text-xs text-foreground font-sans truncate max-w-[160px]" title={scan.targetUrl}>{scan.targetUrl}</div>
                    </td>
                    <td className="p-4 text-muted-foreground text-xs">{format(new Date(scan.createdAt), "yyyy-MM-dd HH:mm")}</td>
                    <td className="p-4">
                      <span className="flex items-center gap-1 text-xs uppercase">
                        <Cpu className="w-3 h-3 text-cyan-500" />{scan.scanType}
                      </span>
                    </td>
                    <td className="p-4">
                      <span className={`px-2 py-0.5 border text-[10px] uppercase tracking-wider ${statusColor[scan.status] || "text-muted-foreground border-border"}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="p-4 text-center">
                      <div className="flex items-center justify-center gap-1 font-mono text-xs">
                        <span className="text-red-500">{scan.criticalCount}</span>
                        <span className="text-border">/</span>
                        <span className="text-orange-500">{scan.highCount}</span>
                        <span className="text-border">/</span>
                        <span className="text-yellow-500">{scan.mediumCount}</span>
                        <span className="text-border">/</span>
                        <span className="text-cyan-500">{scan.lowCount}</span>
                      </div>
                    </td>
                    <td className="p-4">
                      {scan.status === "completed" && (
                        <div className="flex gap-1.5">
                          <Link href={`/scans/${scan.id}/recon`} title="RECON"><Globe className="w-3.5 h-3.5 text-cyan-400" /></Link>
                          <Link href={`/scans/${scan.id}/ai-brain`} title="AI BRAIN"><Brain className="w-3.5 h-3.5 text-purple-400" /></Link>
                          <Link href={`/scans/${scan.id}/graph`} title="GRAPH"><Network className="w-3.5 h-3.5 text-orange-400" /></Link>
                          <Link href={`/scans/${scan.id}/exploit`} title="EXPLOIT"><Zap className="w-3.5 h-3.5 text-red-400" /></Link>
                        </div>
                      )}
                    </td>
                    <td className="p-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Link href={`/scans/${scan.id}/${scan.status === "completed" ? "report" : "live"}`}>
                          <ExternalLink className="w-4 h-4 text-cyan-400 hover:text-cyan-300 transition-colors" />
                        </Link>
                        <button onClick={() => handleDelete(scan.id, scan.targetUrl)}>
                          <Trash2 className="w-4 h-4 text-red-500/60 hover:text-red-500 transition-colors" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {scans.length === 0 && (
                  <tr><td colSpan={7} className="p-8 text-center text-muted-foreground font-mono text-xs">NO_SCANS_FOUND</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Layout>
  );
}
