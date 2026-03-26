import { useState, useCallback } from "react";
import { Layout } from "@/components/layout";
import { Crosshair, Play, Download, AlertTriangle, CheckCircle, RefreshCw, Loader, Info } from "lucide-react";
import { cn } from "@/lib/utils";

interface IntruderResult {
  payloads: string[]; points: string[];
  statusCode: number; responseLength: number;
  responseTime: number; interesting: boolean; evidence?: string;
}

const VULN_TYPES = [
  { id: "xss", label: "XSS" }, { id: "sqli", label: "SQLi" },
  { id: "lfi", label: "LFI" }, { id: "cmdi", label: "CMDi" },
  { id: "ssrf", label: "SSRF" }, { id: "xxe", label: "XXE" },
  { id: "ssti", label: "SSTI" }, { id: "open_redirect", label: "Redirect" },
  { id: "auth_bypass", label: "Auth Bypass" }, { id: "idor", label: "IDOR" },
  { id: "fuzzing", label: "Fuzzing" },
];

const ATTACK_TYPES = [
  { id: "sniper", label: "SNIPER", desc: "One position at a time, all payloads. Best for single injection point." },
  { id: "battering_ram", label: "BATTERING RAM", desc: "Same payload in ALL positions simultaneously." },
  { id: "pitchfork", label: "PITCHFORK", desc: "Parallel: Set1[i]→Pos1, Set2[i]→Pos2. For credential stuffing." },
  { id: "cluster_bomb", label: "CLUSTER BOMB", desc: "Cartesian product of all sets. Tests every combination." },
];

export default function IntruderPage() {
  const [url, setUrl] = useState("");
  const [method, setMethod] = useState("POST");
  const [headers, setHeaders] = useState('{"Content-Type": "application/json"}');
  const [bodyTemplate, setBodyTemplate] = useState('{"username": "§user§", "password": "§pass§"}');
  const [attackType, setAttackType] = useState("sniper");
  const [insertionPoints, setInsertionPoints] = useState("user");
  const [selectedVuln, setSelectedVuln] = useState("sqli");
  const [cveId, setCveId] = useState("");
  const [loadingPayloads, setLoadingPayloads] = useState(false);
  const [payloadSet1, setPayloadSet1] = useState<string[]>([]);
  const [payloadSet2, setPayloadSet2] = useState<string[]>([]);
  const [customSet1, setCustomSet1] = useState("");
  const [customSet2, setCustomSet2] = useState("");
  const [payloadSource, setPayloadSource] = useState("");
  const [results, setResults] = useState<IntruderResult[]>([]);
  const [running, setRunning] = useState(false);
  const [activeTab, setActiveTab] = useState<"config"|"payloads"|"results">("config");

  const fetchPayloads = useCallback(async (setNum: 1|2) => {
    setLoadingPayloads(true);
    try {
      const ep = cveId ? `/api/tools/payloads/cve/${cveId}` : `/api/tools/payloads/${selectedVuln}?limit=100`;
      const res = await fetch(ep, { credentials: "include" });
      const data = await res.json();
      const p = data.payloads || [];
      if (setNum === 1) setPayloadSet1(p);
      else setPayloadSet2(p);
      setPayloadSource(`${p.length} payloads loaded (${data.source || "PayloadsAllTheThings"})`);
    } catch { setPayloadSource("Failed to load"); }
    finally { setLoadingPayloads(false); }
  }, [selectedVuln, cveId]);

  const getSet = (custom: string, loaded: string[]) => {
    const c = custom.split("\n").map(p => p.trim()).filter(Boolean);
    return c.length > 0 ? c : loaded;
  };

  const run = async () => {
    if (!url) return;
    const s1 = getSet(customSet1, payloadSet1);
    const s2 = getSet(customSet2, payloadSet2);
    if (s1.length === 0) { alert("Load or enter payloads for Set 1 first"); return; }
    setRunning(true); setResults([]); setActiveTab("results");
    try {
      let parsedHeaders: Record<string, string> = {};
      try { parsedHeaders = JSON.parse(headers); } catch { }
      const points = insertionPoints.split(",").map(p => p.trim()).filter(Boolean);
      const res = await fetch("/api/tools/intruder", {
        method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include",
        body: JSON.stringify({ url, method, headers: parsedHeaders, bodyTemplate, attackType, insertionPoints: points, payloadSets: [s1, s2] }),
      });
      const data = await res.json();
      setResults(data.results || []);
    } catch (e) { console.error(e); }
    finally { setRunning(false); }
  };

  const exportCSV = () => {
    const rows = [["Payloads","Status","Length","Time(ms)","Interesting","Evidence"]];
    results.forEach(r => rows.push([r.payloads.join("|"), String(r.statusCode), String(r.responseLength), String(r.responseTime), String(r.interesting), r.evidence?.substring(0,100)||""]));
    const csv = rows.map(r => r.map(c => `"${c.replace(/"/g,'""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "intruder.csv"; a.click();
  };

  const interesting = results.filter(r => r.interesting);
  const needsTwoSets = ["pitchfork", "cluster_bomb"].includes(attackType);

  return (
    <Layout>
      <div className="space-y-3 animate-in fade-in duration-500">
        <header className="border-b border-primary/20 pb-3 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-display font-bold flex items-center gap-2">
              <Crosshair className="w-5 h-5 text-red-400"/> INTRUDER
            </h1>
            <p className="text-[10px] font-mono text-muted-foreground mt-0.5">
              Sniper · Battering Ram · Pitchfork · Cluster Bomb — Real HTTP payload injection
            </p>
          </div>
          <div className="flex gap-2">
            {results.length > 0 && (
              <button onClick={exportCSV} className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1">
                <Download className="w-3 h-3"/> CSV
              </button>
            )}
            <button onClick={run} disabled={running}
              className={cn("cyber-button !py-1.5 !px-4 text-xs flex items-center gap-2",
                running && "opacity-60 cursor-not-allowed")}>
              {running ? <><RefreshCw className="w-3.5 h-3.5 animate-spin"/>ATTACKING...</> : <><Play className="w-3.5 h-3.5"/>LAUNCH</>}
            </button>
          </div>
        </header>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-primary/10">
          {(["config","payloads","results"] as const).map(t => (
            <button key={t} onClick={() => setActiveTab(t)}
              className={cn("px-4 py-2 font-mono text-xs border-b-2 transition-all uppercase",
                activeTab === t ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground")}>
              {t} {t === "results" && results.length > 0 && `(${results.length})`}
            </button>
          ))}
        </div>

        {/* CONFIG TAB */}
        {activeTab === "config" && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="space-y-3">
              <div className="cyber-box p-4 space-y-3">
                <label className="font-mono text-xs text-primary">TARGET</label>
                <div className="flex gap-2">
                  <select value={method} onChange={e => setMethod(e.target.value)}
                    className="bg-black/50 border border-primary/30 px-2 py-2 font-mono text-xs text-foreground focus:outline-none w-24">
                    {["GET","POST","PUT","PATCH","DELETE"].map(m => <option key={m}>{m}</option>)}
                  </select>
                  <input value={url} onChange={e => setUrl(e.target.value)}
                    className="flex-1 bg-black/50 border border-primary/30 px-3 py-2 font-mono text-sm text-foreground focus:outline-none focus:border-primary"
                    placeholder="https://target.com/api/login"/>
                </div>
                <div>
                  <label className="font-mono text-[10px] text-muted-foreground">HEADERS (JSON)</label>
                  <textarea value={headers} onChange={e => setHeaders(e.target.value)} rows={2}
                    className="w-full bg-black/50 border border-primary/30 p-2 font-mono text-xs text-foreground focus:outline-none mt-1 resize-none"/>
                </div>
                <div>
                  <label className="font-mono text-[10px] text-muted-foreground">BODY TEMPLATE (mark positions with §name§)</label>
                  <textarea value={bodyTemplate} onChange={e => setBodyTemplate(e.target.value)} rows={3}
                    className="w-full bg-black/50 border border-primary/30 p-2 font-mono text-xs text-foreground focus:outline-none mt-1 resize-none"/>
                </div>
                <div>
                  <label className="font-mono text-[10px] text-muted-foreground">INSERTION POINTS (comma separated, match §names§)</label>
                  <input value={insertionPoints} onChange={e => setInsertionPoints(e.target.value)}
                    className="w-full bg-black/50 border border-primary/30 px-3 py-2 font-mono text-sm text-foreground focus:outline-none mt-1"
                    placeholder="user, pass"/>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <div className="cyber-box p-4 space-y-3">
                <label className="font-mono text-xs text-primary">ATTACK TYPE</label>
                {ATTACK_TYPES.map(at => (
                  <label key={at.id} onClick={() => setAttackType(at.id)}
                    className={cn("flex items-start gap-3 p-3 border cursor-pointer transition-all",
                      attackType === at.id ? "border-primary bg-primary/10" : "border-border/30 hover:border-primary/30")}>
                    <div className={cn("w-3 h-3 rounded-full border-2 mt-0.5 shrink-0 transition-all",
                      attackType === at.id ? "border-primary bg-primary" : "border-muted-foreground")}/>
                    <div>
                      <div className={cn("font-mono text-xs font-bold", attackType === at.id ? "text-primary" : "text-foreground")}>{at.label}</div>
                      <div className="font-mono text-[10px] text-muted-foreground mt-0.5">{at.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* PAYLOADS TAB */}
        {activeTab === "payloads" && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {[1, ...(needsTwoSets ? [2] : [])].map(setNum => (
              <div key={setNum} className="cyber-box p-4 space-y-3">
                <label className="font-mono text-xs text-primary">PAYLOAD SET {setNum}</label>

                <div className="flex flex-wrap gap-1">
                  {VULN_TYPES.map(v => (
                    <button key={v.id} onClick={() => setSelectedVuln(v.id)}
                      className={cn("px-2 py-1 font-mono text-[10px] border transition-all",
                        selectedVuln === v.id ? "border-primary bg-primary/20 text-primary" : "border-border/50 text-muted-foreground hover:border-primary/30")}>
                      {v.label}
                    </button>
                  ))}
                </div>

                <div className="flex gap-2">
                  <input value={cveId} onChange={e => setCveId(e.target.value.toUpperCase())}
                    className="flex-1 bg-black/50 border border-primary/30 p-2 font-mono text-xs text-foreground focus:outline-none"
                    placeholder="CVE-2024-XXXX (optional)"/>
                  <button onClick={() => fetchPayloads(setNum as 1|2)} disabled={loadingPayloads}
                    className="cyber-button !py-2 !px-3 text-xs flex items-center gap-1.5">
                    {loadingPayloads ? <Loader className="w-3 h-3 animate-spin"/> : <RefreshCw className="w-3 h-3"/>}
                    LOAD
                  </button>
                </div>

                {payloadSource && <div className="font-mono text-[10px] text-primary border border-primary/20 bg-primary/5 p-2">✓ {payloadSource}</div>}

                <div>
                  <label className="font-mono text-[10px] text-muted-foreground">
                    CUSTOM PAYLOADS (one per line — overrides loaded)
                    {setNum === 1 && payloadSet1.length > 0 && <span className="ml-2 text-primary">{payloadSet1.length} loaded</span>}
                    {setNum === 2 && payloadSet2.length > 0 && <span className="ml-2 text-primary">{payloadSet2.length} loaded</span>}
                  </label>
                  <textarea
                    value={setNum === 1 ? customSet1 : customSet2}
                    onChange={e => setNum === 1 ? setCustomSet1(e.target.value) : setCustomSet2(e.target.value)}
                    rows={8}
                    className="w-full bg-black/50 border border-primary/30 p-2 font-mono text-xs text-foreground focus:outline-none mt-1 resize-none"
                    placeholder={"payload1\npayload2\npayload3"}/>
                </div>

                <div className="font-mono text-[10px] text-muted-foreground">
                  {(() => {
                    const s = getSet(setNum === 1 ? customSet1 : customSet2, setNum === 1 ? payloadSet1 : payloadSet2);
                    return s.length > 0
                      ? <span className="text-primary">{s.length} payloads ready</span>
                      : <span className="text-yellow-400">⚠ Load or enter payloads</span>;
                  })()}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* RESULTS TAB */}
        {activeTab === "results" && (
          <div className="space-y-3">
            {results.length > 0 && (
              <div className="flex gap-4 font-mono text-xs">
                <span className="text-primary">{results.length} requests</span>
                <span className="text-red-400 font-bold">{interesting.length} interesting</span>
                <span className="text-green-400">{results.filter(r => r.statusCode === 200).length} × 200</span>
                <span className="text-red-400">{results.filter(r => r.statusCode === 500).length} × 500</span>
                <span className="text-muted-foreground">{results.filter(r => r.responseTime > 4000).length} slow</span>
              </div>
            )}

            <div className="cyber-box overflow-hidden">
              <div className="grid grid-cols-12 gap-1 p-2 border-b border-primary/20 font-mono text-[10px] text-muted-foreground bg-black/30">
                <span className="col-span-5">PAYLOAD(S)</span>
                <span className="col-span-2 text-center">STATUS</span>
                <span className="col-span-2 text-center">LENGTH</span>
                <span className="col-span-2 text-center">TIME</span>
                <span className="col-span-1 text-center">⚑</span>
              </div>
              <div className="max-h-[500px] overflow-y-auto">
                {results.length === 0 ? (
                  <div className="p-8 text-center font-mono text-xs text-muted-foreground">
                    <Crosshair className="w-8 h-8 mx-auto mb-2 opacity-20"/>
                    Configure → Load Payloads → Launch Attack
                  </div>
                ) : results.map((r, i) => (
                  <div key={i} className={cn("grid grid-cols-12 gap-1 p-2 border-b border-border/20 font-mono text-[10px] hover:bg-white/5 transition-colors",
                    r.interesting && "bg-red-500/5 border-red-500/20")}>
                    <span className="col-span-5 truncate text-foreground/80" title={r.payloads.join(" | ")}>{r.payloads.join(" | ")}</span>
                    <span className={cn("col-span-2 text-center font-bold",
                      r.statusCode===200?"text-green-400":r.statusCode>=500?"text-red-400":r.statusCode===0?"text-muted-foreground":"text-yellow-400")}>
                      {r.statusCode||"ERR"}
                    </span>
                    <span className="col-span-2 text-center text-foreground/60">{r.responseLength}</span>
                    <span className={cn("col-span-2 text-center", r.responseTime>4000?"text-red-400 font-bold":"text-foreground/60")}>
                      {r.responseTime}ms
                    </span>
                    <span className="col-span-1 flex justify-center">
                      {r.interesting ? <AlertTriangle className="w-3 h-3 text-red-400"/> : <CheckCircle className="w-3 h-3 text-muted-foreground/30"/>}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {interesting.length > 0 && (
              <div className="cyber-box p-3 border-red-500/30 bg-red-500/5">
                <h3 className="font-mono text-xs text-red-400 mb-2 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3"/> INTERESTING ({interesting.length})
                </h3>
                {interesting.slice(0, 10).map((r, i) => (
                  <div key={i} className="mb-2 p-2 bg-black/30 border border-red-500/20">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-[9px] text-red-300 font-bold">HTTP {r.statusCode}</span>
                      <span className="font-mono text-[9px] text-muted-foreground">{r.responseTime}ms · {r.responseLength}B</span>
                    </div>
                    <div className="font-mono text-[10px] text-yellow-300">Payload: {r.payloads.join(" | ")}</div>
                    {r.evidence && <div className="font-mono text-[9px] text-muted-foreground mt-1 break-all line-clamp-2">{r.evidence}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </Layout>
  );
}
