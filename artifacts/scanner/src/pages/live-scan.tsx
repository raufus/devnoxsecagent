import { useEffect, useRef, useState } from "react";
import { useLocation, useParams } from "wouter";
import { useGetScan, useCancelScan } from "@workspace/api-client-react";
import { Layout } from "@/components/layout";
import { useScanStream } from "@/hooks/use-scan-stream";
import { Terminal, StopCircle, Activity, ChevronRight, FileText, AlertTriangle, Bug, Shield } from "lucide-react";
import { formatUptime, getSeverityColor } from "@/lib/utils";
import { format } from "date-fns";
import { cn } from "@/lib/utils";

const PHASES = [
  { id: "idle", label: "INIT" },
  { id: "recon", label: "RECON" },
  { id: "scanning", label: "ATTACK" },
  { id: "exploitation", label: "EXPLOIT" },
  { id: "ai_analysis", label: "AI_BRAIN" },
  { id: "done", label: "DONE" },
];

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export default function LiveScan() {
  const { id } = useParams();
  const [, setLocation] = useLocation();
  const [activeTab, setActiveTab] = useState<"terminal" | "findings">("terminal");

  const { data: scan, isLoading } = useGetScan(id!, {
    query: {
      refetchInterval: (data) =>
        data?.state?.data?.status === "running" || data?.state?.data?.status === "pending" ? 2000 : false,
    },
  });

  const { events, findings, connected } = useScanStream(id);
  const cancelScan = useCancelScan();
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [events]);

  useEffect(() => {
    if (findings.length > 0 && activeTab === "terminal") {
      // Auto switch to findings tab when first finding appears
    }
  }, [findings.length]);

  if (isLoading || !scan) {
    return (
      <Layout>
        <div className="flex flex-col items-center justify-center h-64 text-primary font-mono space-y-4">
          <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin shadow-[0_0_15px_rgba(0,255,128,0.5)]" />
          <p className="animate-pulse tracking-widest text-sm">CONNECTING TO SESSION...</p>
        </div>
      </Layout>
    );
  }

  const isRunning = scan.status === "running" || scan.status === "pending";
  const currentPhaseIndex = PHASES.findIndex((p) => p.id === scan.currentPhase);

  const handleCancel = async () => {
    if (confirm("ABORT OPERATION? All active threads will be terminated.")) {
      await cancelScan.mutateAsync({ scanId: id! });
    }
  };

  const sortedFindings = [...findings].sort((a, b) =>
    SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  return (
    <Layout>
      <div className="flex flex-col gap-3 sm:gap-4 animate-in fade-in duration-500">
        {/* Header */}
        <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-primary/20 pb-3 sm:pb-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono mb-1">
              <span className="text-muted-foreground">TARGET:</span>
              <span className="text-cyan-400 px-2 py-0.5 bg-cyan-400/10 border border-cyan-400/30 truncate max-w-[200px] sm:max-w-sm text-xs">
                {scan.targetUrl}
              </span>
              <span className={cn(
                "px-2 py-0.5 border uppercase text-[10px] font-bold tracking-widest",
                isRunning ? "text-primary border-primary bg-primary/10 animate-pulse" : "text-muted-foreground border-border"
              )}>
                {scan.status}
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl lg:text-3xl">LIVE_TELEMETRY</h1>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <div className="text-right font-mono">
              <div className="text-[10px] text-muted-foreground">UPTIME</div>
              <div className="text-base sm:text-lg text-primary">{formatUptime(scan.startedAt, scan.completedAt)}</div>
            </div>
            {isRunning ? (
              <button onClick={handleCancel} className="cyber-button !border-red-500 !text-red-500 hover:!bg-red-500 hover:!text-black flex items-center gap-1.5 text-xs sm:text-sm !py-2 !px-3">
                <StopCircle className="w-4 h-4" /> ABORT
              </button>
            ) : (
              <button onClick={() => setLocation(`/scans/${id}/report`)} className="cyber-button flex items-center gap-1.5 text-xs sm:text-sm !py-2 !px-3">
                <FileText className="w-4 h-4" /> VIEW REPORT
              </button>
            )}
          </div>
        </header>

        {/* Phase Stepper */}
        <div className="cyber-box p-2.5 px-3 flex items-center overflow-x-auto gap-1 scrollbar-none">
          {PHASES.map((phase, idx) => {
            const isPast = idx < currentPhaseIndex;
            const isCurrent = idx === currentPhaseIndex;
            return (
              <div key={phase.id} className="flex items-center gap-1 shrink-0">
                <div className={cn(
                  "flex items-center justify-center h-5 w-5 border font-mono text-[9px] shrink-0",
                  isPast ? "bg-primary text-black border-primary shadow-[0_0_8px_rgba(0,255,128,0.5)]" :
                    isCurrent ? "bg-primary/20 text-primary border-primary animate-pulse" :
                      "bg-transparent text-muted-foreground border-border"
                )}>
                  {idx + 1}
                </div>
                <span className={cn(
                  "font-mono text-[10px] tracking-wider",
                  isCurrent ? "text-primary font-bold" : isPast ? "text-foreground" : "text-muted-foreground"
                )}>
                  {phase.label}
                </span>
                {idx < PHASES.length - 1 && (
                  <ChevronRight className={cn("w-3 h-3 mx-0.5 shrink-0", isPast ? "text-primary" : "text-muted-foreground/30")} />
                )}
              </div>
            );
          })}
        </div>

        {/* Progress Bar */}
        <div className="cyber-box p-1 relative h-5 overflow-hidden shrink-0">
          <div className="absolute inset-0 bg-primary/10" />
          <div
            className="absolute inset-y-0 left-0 bg-primary shadow-[0_0_20px_rgba(0,255,128,0.8)] transition-all duration-1000 ease-out"
            style={{ width: `${scan.progress}%` }}
          />
          <span className="absolute inset-0 flex items-center justify-center text-[10px] font-mono font-bold mix-blend-difference text-white">
            {scan.progress}%
          </span>
        </div>

        {/* Severity Counters */}
        <div className="grid grid-cols-5 gap-1.5 sm:gap-2">
          {[
            { label: "CRITICAL", count: scan.criticalCount, c: "text-red-500 border-red-500/40 bg-red-500/5" },
            { label: "HIGH", count: scan.highCount, c: "text-orange-500 border-orange-500/40 bg-orange-500/5" },
            { label: "MEDIUM", count: scan.mediumCount, c: "text-yellow-500 border-yellow-500/40 bg-yellow-500/5" },
            { label: "LOW", count: scan.lowCount, c: "text-cyan-500 border-cyan-500/40 bg-cyan-500/5" },
            { label: "INFO", count: scan.infoCount, c: "text-gray-400 border-gray-500/40 bg-gray-500/5" },
          ].map(({ label, count, c }) => (
            <div key={label} className={cn("p-2 border flex flex-col items-center gap-0.5", c)}>
              <span className="font-display font-bold text-lg sm:text-2xl">{count}</span>
              <span className="font-mono text-[8px] sm:text-[10px] text-center leading-tight opacity-80">{label}</span>
            </div>
          ))}
        </div>

        {/* Tab Switcher + Panels */}
        <div className="flex gap-1 font-mono text-xs">
          <button
            onClick={() => setActiveTab("terminal")}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 border transition-all",
              activeTab === "terminal" ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground"
            )}
          >
            <Terminal className="w-3.5 h-3.5" /> TERMINAL
          </button>
          <button
            onClick={() => setActiveTab("findings")}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 border transition-all relative",
              activeTab === "findings" ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground"
            )}
          >
            <Bug className="w-3.5 h-3.5" /> LIVE FINDINGS
            {findings.length > 0 && (
              <span className="ml-1 px-1 py-0 bg-red-500 text-white text-[9px] font-bold rounded-sm">
                {findings.length}
              </span>
            )}
          </button>
        </div>

        {/* Terminal Panel */}
        {activeTab === "terminal" && (
          <div className="cyber-box p-0 flex flex-col h-[340px] sm:h-[400px] bg-[#050505]">
            <div className="bg-primary/10 border-b border-primary/20 p-2 px-3 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2">
                <Terminal className="w-3 h-3 text-primary" />
                <span className="font-mono text-[10px] text-primary">devnox.sys.stdout</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className={cn(
                  "w-1.5 h-1.5 rounded-full",
                  connected && isRunning ? "bg-primary shadow-[0_0_5px_#00ff80] animate-pulse" : "bg-red-500"
                )} />
                <span className="font-mono text-[10px] text-muted-foreground">
                  {connected && isRunning ? "STREAM_ACTIVE" : "OFFLINE"}
                </span>
              </div>
            </div>
            <div ref={terminalRef} className="flex-1 p-3 font-mono text-[11px] overflow-y-auto space-y-0.5">
              <div className="text-primary/40 mb-2">
                [DEVNOX] Autonomous Security Assessment v2.0<br />
                [DEVNOX] Target: {scan.targetUrl}<br />
                ──────────────────────────────────────────
              </div>
              {events.length === 0 && isRunning && (
                <div className="flex items-center gap-2 text-primary animate-pulse">
                  <span className="text-primary">▶</span> Initializing autonomous scan engine...
                </div>
              )}
              {events.map((ev, i) => (
                <div key={ev.id || i} className="flex gap-2 break-words py-0.5">
                  <span className="text-muted-foreground/40 shrink-0 text-[10px]">
                    [{format(new Date(ev.createdAt), "HH:mm:ss")}]
                  </span>
                  <span className={cn("flex-1 min-w-0 break-words",
                    ev.level === "error" ? "text-red-400" :
                      ev.level === "warning" ? "text-yellow-400" :
                        ev.level === "success" ? "text-cyan-300" :
                          "text-foreground/80"
                  )}>
                    {ev.message}
                  </span>
                </div>
              ))}
              {!isRunning && events.length > 0 && (
                <div className="text-primary/40 mt-3 border-t border-primary/20 pt-2">
                  [DEVNOX] Scan complete. {findings.length} findings recorded. Press VIEW REPORT for full analysis.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Live Findings Panel */}
        {activeTab === "findings" && (
          <div className="cyber-box p-0 flex flex-col h-[340px] sm:h-[400px] bg-[#050505]">
            <div className="bg-primary/10 border-b border-primary/20 p-2 px-3 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2">
                <Shield className="w-3 h-3 text-primary" />
                <span className="font-mono text-[10px] text-primary">live.findings — {findings.length} discovered</span>
              </div>
              {isRunning && (
                <div className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_5px_#00ff80] animate-pulse" />
                  <span className="font-mono text-[10px] text-primary">SCANNING</span>
                </div>
              )}
            </div>
            <div className="flex-1 overflow-y-auto divide-y divide-border/30">
              {sortedFindings.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground font-mono text-xs gap-2">
                  {isRunning ? (
                    <>
                      <Activity className="w-6 h-6 animate-pulse text-primary/40" />
                      <span>Probing target — findings will appear here</span>
                    </>
                  ) : (
                    <>
                      <AlertTriangle className="w-6 h-6 text-primary/40" />
                      <span>No findings detected</span>
                    </>
                  )}
                </div>
              ) : (
                sortedFindings.map((f, i) => (
                  <div key={f.id || i} className="p-3 hover:bg-white/5 transition-colors">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={cn("px-1.5 py-0.5 font-mono text-[9px] uppercase border shrink-0", getSeverityColor(f.severity))}>
                        {f.severity}
                      </span>
                      <span className="font-mono text-[10px] text-muted-foreground border border-border/50 px-1.5 py-0.5 shrink-0">
                        {f.type}
                      </span>
                      {f.cvssScore && (
                        <span className="font-mono text-[9px] text-primary border border-primary/30 px-1.5 py-0.5 shrink-0">
                          CVSS {f.cvssScore}
                        </span>
                      )}
                    </div>
                    <p className="font-bold text-xs text-foreground mb-1 leading-tight">{f.title}</p>
                    {f.endpoint && (
                      <p className="font-mono text-[10px] text-cyan-400/80 truncate">{f.endpoint}</p>
                    )}
                    {f.parameter && (
                      <p className="font-mono text-[10px] text-red-400/80">param: {f.parameter}</p>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
