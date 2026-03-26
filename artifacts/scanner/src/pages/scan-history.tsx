import { useListScans, useDeleteScan } from "@workspace/api-client-react";
import { Layout } from "@/components/layout";
import { Link } from "wouter";
import { format } from "date-fns";
import { Trash2, ExternalLink, ShieldAlert, Cpu, Globe, Brain, Network, Zap, FileText } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function ScanHistory() {
  const { data, isLoading } = useListScans();
  const deleteScan = useDeleteScan();
  const { toast } = useToast();

  const handleDelete = async (id: string) => {
    if (confirm("PURGE RECORD? This action cannot be undone.")) {
      try {
        await deleteScan.mutateAsync({ scanId: id });
        toast({ title: "RECORD_PURGED", description: "Scan data has been permanently deleted." });
      } catch {
        toast({ title: "ERROR", description: "Failed to delete record.", variant: "destructive" });
      }
    }
  };

  const scans = data?.scans || [];

  return (
    <Layout>
      <div className="space-y-6 animate-in fade-in duration-500">
        <header>
          <h1 className="text-2xl sm:text-3xl flex items-center gap-3">
            <ShieldAlert className="w-7 h-7 text-primary shrink-0" />
            OPERATIONAL_HISTORY
          </h1>
          <p className="text-muted-foreground font-mono mt-1 text-xs sm:text-sm">
            // Archival records of past reconnaissance and exploitation
          </p>
        </header>

        {/* Desktop table */}
        <div className="cyber-box overflow-hidden hidden md:block">
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-sm border-collapse">
              <thead>
                <tr className="border-b border-primary/30 bg-black/50 text-primary/70">
                  <th className="p-4 font-normal tracking-wider">TARGET</th>
                  <th className="p-4 font-normal tracking-wider">DATE</th>
                  <th className="p-4 font-normal tracking-wider">MODE</th>
                  <th className="p-4 font-normal tracking-wider">STATUS</th>
                  <th className="p-4 font-normal tracking-wider text-center">C / H / M</th>
                  <th className="p-4 font-normal tracking-wider">INTEL MODULES</th>
                  <th className="p-4 font-normal tracking-wider text-right">ACTIONS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {isLoading ? (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-muted-foreground">
                      QUERYING_ARCHIVES...
                    </td>
                  </tr>
                ) : scans.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-muted-foreground">
                      NO_RECORDS_FOUND
                    </td>
                  </tr>
                ) : (
                  scans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-primary/5 transition-colors group">
                      <td className="p-4 truncate max-w-[180px] text-foreground font-sans text-sm">
                        {scan.targetUrl}
                      </td>
                      <td className="p-4 text-muted-foreground text-xs">
                        {format(new Date(scan.createdAt), "yyyy-MM-dd HH:mm")}
                      </td>
                      <td className="p-4 uppercase text-xs">
                        <span className="flex items-center gap-1">
                          <Cpu className="w-3 h-3 text-cyan-500" /> {scan.scanType}
                        </span>
                      </td>
                      <td className="p-4">
                        <span
                          className={`px-2 py-1 text-[10px] border tracking-wider uppercase ${
                            scan.status === "running"
                              ? "text-primary border-primary animate-pulse"
                              : scan.status === "completed"
                              ? "text-cyan-400 border-cyan-400/50"
                              : scan.status === "failed"
                              ? "text-red-500 border-red-500/50"
                              : "text-muted-foreground border-border"
                          }`}
                        >
                          {scan.status}
                        </span>
                      </td>
                      <td className="p-4 text-center">
                        {scan.status === "completed" || scan.status === "running" ? (
                          <div className="flex items-center justify-center gap-1 font-mono text-sm">
                            <span className="text-red-500 w-5 text-right">{scan.criticalCount}</span>
                            <span className="text-border">/</span>
                            <span className="text-orange-500 w-5 text-center">{scan.highCount}</span>
                            <span className="text-border">/</span>
                            <span className="text-yellow-500 w-5 text-left">{scan.mediumCount}</span>
                          </div>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </td>
                      <td className="p-4">
                        {scan.status === "completed" ? (
                          <div className="flex items-center gap-2">
                            <Link href={`/scans/${scan.id}/recon`} title="RECON INTEL">
                              <Globe className="w-4 h-4 text-cyan-400 hover:text-cyan-300 hover:scale-110 transition-all" />
                            </Link>
                            <Link href={`/scans/${scan.id}/ai-brain`} title="AI BRAIN">
                              <Brain className="w-4 h-4 text-purple-400 hover:text-purple-300 hover:scale-110 transition-all" />
                            </Link>
                            <Link href={`/scans/${scan.id}/graph`} title="GRAPH MAP">
                              <Network className="w-4 h-4 text-orange-400 hover:text-orange-300 hover:scale-110 transition-all" />
                            </Link>
                            <Link href={`/scans/${scan.id}/exploit`} title="EXPLOIT ENGINE">
                              <Zap className="w-4 h-4 text-red-400 hover:text-red-300 hover:scale-110 transition-all" />
                            </Link>
                            <Link href={`/scans/${scan.id}/report`} title="FULL REPORT">
                              <FileText className="w-4 h-4 text-primary hover:text-primary/70 hover:scale-110 transition-all" />
                            </Link>
                          </div>
                        ) : scan.status === "running" ? (
                          <span className="font-mono text-[10px] text-primary animate-pulse">SCANNING...</span>
                        ) : (
                          <span className="text-muted-foreground text-xs font-mono">—</span>
                        )}
                      </td>
                      <td className="p-4 text-right">
                        <div className="flex items-center justify-end gap-3">
                          <Link
                            href={`/scans/${scan.id}/${scan.status === "completed" ? "report" : "live"}`}
                            className="text-cyan-400 hover:text-cyan-300 hover:scale-110 transition-all"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </Link>
                          <button
                            onClick={() => handleDelete(scan.id)}
                            className="text-red-500/70 hover:text-red-500 hover:scale-110 transition-all"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Mobile card list */}
        <div className="md:hidden space-y-3">
          {isLoading ? (
            <div className="cyber-box p-6 text-center text-muted-foreground font-mono text-sm">
              QUERYING_ARCHIVES...
            </div>
          ) : scans.length === 0 ? (
            <div className="cyber-box p-6 text-center text-muted-foreground font-mono text-sm border-dashed">
              NO_RECORDS_FOUND
            </div>
          ) : (
            scans.map((scan) => (
              <div key={scan.id} className="cyber-box p-4 space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <p className="font-sans text-sm text-foreground break-all flex-1">{scan.targetUrl}</p>
                  <span
                    className={`px-2 py-0.5 text-[10px] border tracking-wider uppercase shrink-0 ${
                      scan.status === "running"
                        ? "text-primary border-primary animate-pulse"
                        : scan.status === "completed"
                        ? "text-cyan-400 border-cyan-400/50"
                        : scan.status === "failed"
                        ? "text-red-500 border-red-500/50"
                        : "text-muted-foreground border-border"
                    }`}
                  >
                    {scan.status}
                  </span>
                </div>

                <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] text-muted-foreground">
                  <span>{format(new Date(scan.createdAt), "yyyy-MM-dd HH:mm")}</span>
                  <span className="flex items-center gap-1">
                    <Cpu className="w-2.5 h-2.5 text-cyan-500" /> {scan.scanType.toUpperCase()}
                  </span>
                </div>

                {(scan.status === "completed" || scan.status === "running") && (
                  <div className="flex gap-3 font-mono text-xs">
                    <span className="text-red-500">{scan.criticalCount} CRIT</span>
                    <span className="text-orange-500">{scan.highCount} HIGH</span>
                    <span className="text-yellow-500">{scan.mediumCount} MED</span>
                    <span className="text-cyan-500">{scan.lowCount} LOW</span>
                  </div>
                )}

                {scan.status === "completed" && (
                  <div className="pt-2 border-t border-border/30">
                    <div className="text-[9px] font-mono text-muted-foreground mb-1.5">INTEL MODULES</div>
                    <div className="flex items-center gap-3 flex-wrap">
                      <Link href={`/scans/${scan.id}/recon`} className="flex items-center gap-1 font-mono text-[10px] text-cyan-400">
                        <Globe className="w-3.5 h-3.5" /> RECON
                      </Link>
                      <Link href={`/scans/${scan.id}/ai-brain`} className="flex items-center gap-1 font-mono text-[10px] text-purple-400">
                        <Brain className="w-3.5 h-3.5" /> AI_BRAIN
                      </Link>
                      <Link href={`/scans/${scan.id}/graph`} className="flex items-center gap-1 font-mono text-[10px] text-orange-400">
                        <Network className="w-3.5 h-3.5" /> GRAPH
                      </Link>
                      <Link href={`/scans/${scan.id}/exploit`} className="flex items-center gap-1 font-mono text-[10px] text-red-400">
                        <Zap className="w-3.5 h-3.5" /> EXPLOIT
                      </Link>
                    </div>
                  </div>
                )}
                <div className="flex items-center justify-end gap-4 pt-2 border-t border-border/30">
                  <Link
                    href={`/scans/${scan.id}/${scan.status === "completed" ? "report" : "live"}`}
                    className="text-cyan-400 font-mono text-xs flex items-center gap-1"
                  >
                    <ExternalLink className="w-3.5 h-3.5" /> VIEW
                  </Link>
                  <button
                    onClick={() => handleDelete(scan.id)}
                    className="text-red-500/70 font-mono text-xs flex items-center gap-1"
                  >
                    <Trash2 className="w-3.5 h-3.5" /> DELETE
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </Layout>
  );
}
