import { useState, useEffect, useRef } from "react";
import { Layout } from "@/components/layout";
import { FileText, Trash2, Download, Circle } from "lucide-react";
import { cn } from "@/lib/utils";

interface LogEntry { id: string; timestamp: number; level: "info"|"warn"|"error"|"success"; source: string; message: string; }

const STORAGE_KEY = "devnox_logger";
export function log(level: LogEntry["level"], source: string, message: string) {
  try {
    const entries: LogEntry[] = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    entries.unshift({ id: crypto.randomUUID(), timestamp: Date.now(), level, source, message });
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries.slice(0, 1000)));
  } catch { }
}

export default function LoggerPage() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | undefined>(undefined);

  const load = () => {
    try { setEntries(JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]")); } catch { }
  };

  useEffect(() => {
    load();
    if (autoRefresh) { intervalRef.current = setInterval(load, 2000); }
    return () => clearInterval(intervalRef.current);
  }, [autoRefresh]);

  const clear = () => { localStorage.removeItem(STORAGE_KEY); setEntries([]); };

  const exportLogs = () => {
    const blob = new Blob([JSON.stringify(entries, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "devnox_logs.json"; a.click();
  };

  const filtered = entries.filter(e =>
    (filter === "ALL" || e.level === filter.toLowerCase()) &&
    (!search || e.message.toLowerCase().includes(search.toLowerCase()) || e.source.toLowerCase().includes(search.toLowerCase()))
  );

  const levelColor: Record<string, string> = {
    info: "text-cyan-400", warn: "text-yellow-400", error: "text-red-400", success: "text-primary"
  };

  return (
    <Layout>
      <div className="space-y-3 animate-in fade-in duration-500">
        <header className="border-b border-primary/20 pb-3 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-display font-bold flex items-center gap-2">
              <FileText className="w-5 h-5 text-primary" /> LOGGER
            </h1>
            <p className="text-[10px] font-mono text-muted-foreground mt-0.5">System activity log — all tool operations</p>
          </div>
          <div className="flex gap-2 items-center">
            <label className="flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground cursor-pointer">
              <Circle className={cn("w-2 h-2", autoRefresh ? "text-primary fill-primary animate-pulse" : "text-muted-foreground")} />
              <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} className="hidden" />
              LIVE
            </label>
            <button onClick={exportLogs} disabled={entries.length === 0} className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1">
              <Download className="w-3 h-3" /> EXPORT
            </button>
            <button onClick={clear} className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1 !border-red-400/30 !text-red-400">
              <Trash2 className="w-3 h-3" /> CLEAR
            </button>
          </div>
        </header>

        <div className="flex flex-wrap gap-2 items-center">
          <input value={search} onChange={e => setSearch(e.target.value)}
            className="flex-1 min-w-48 bg-black/50 border border-primary/30 px-3 py-1.5 font-mono text-xs text-foreground focus:outline-none focus:border-primary"
            placeholder="Search logs..." />
          <div className="flex gap-1">
            {["ALL","INFO","WARN","ERROR","SUCCESS"].map(l => (
              <button key={l} onClick={() => setFilter(l)}
                className={cn("px-2 py-1.5 font-mono text-[10px] border transition-all",
                  filter === l ? "border-primary text-primary bg-primary/10" : "border-border/30 text-muted-foreground")}>
                {l}
              </button>
            ))}
          </div>
          <span className="font-mono text-[10px] text-muted-foreground">{filtered.length} entries</span>
        </div>

        <div className="cyber-box overflow-hidden">
          <div className="overflow-y-auto font-mono text-[10px]" style={{ maxHeight: "600px" }}>
            {filtered.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground">
                <FileText className="w-8 h-8 mx-auto mb-2 opacity-20" />
                No log entries yet
              </div>
            ) : filtered.map(e => (
              <div key={e.id} className="flex items-start gap-3 p-2 border-b border-border/10 hover:bg-white/5 transition-colors">
                <span className="text-muted-foreground/50 shrink-0 w-20">{new Date(e.timestamp).toLocaleTimeString()}</span>
                <span className={cn("font-bold shrink-0 w-14 uppercase", levelColor[e.level] || "text-muted-foreground")}>{e.level}</span>
                <span className="text-cyan-400/70 shrink-0 w-20 truncate">{e.source}</span>
                <span className="text-foreground/80 break-all">{e.message}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Layout>
  );
}
