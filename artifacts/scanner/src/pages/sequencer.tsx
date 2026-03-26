import { useState } from "react";
import { Layout } from "@/components/layout";
import { Shuffle, Play, BarChart2, AlertTriangle, CheckCircle } from "lucide-react";
import { cn } from "@/lib/utils";

interface TokenSample { token: string; length: number; entropy: number; charSet: string; }

function calcEntropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / s.length; return sum + p * Math.log2(p);
  }, 0);
}

function getCharSet(s: string): string {
  const sets = [];
  if (/[a-z]/.test(s)) sets.push("lowercase");
  if (/[A-Z]/.test(s)) sets.push("uppercase");
  if (/[0-9]/.test(s)) sets.push("digits");
  if (/[^a-zA-Z0-9]/.test(s)) sets.push("special");
  return sets.join("+");
}

export default function SequencerPage() {
  const [url, setUrl] = useState(""); const [method, setMethod] = useState("GET");
  const [headers, setHeaders] = useState('{"Cookie": "session=§token§"}');
  const [tokenParam, setTokenParam] = useState("token");
  const [sampleCount, setSampleCount] = useState(50);
  const [samples, setSamples] = useState<TokenSample[]>([]);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);

  const run = async () => {
    if (!url) return;
    setRunning(true); setSamples([]); setProgress(0);
    const collected: TokenSample[] = [];
    try {
      let h: Record<string, string> = {};
      try { h = JSON.parse(headers); } catch { }
      for (let i = 0; i < sampleCount; i++) {
        try {
          const res = await fetch("/api/tools/repeater", {
            method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include",
            body: JSON.stringify({ method, url, headers: h, body: "", followRedirects: true, timeout: 8000 }),
          });
          const data = await res.json();
          // Extract token from Set-Cookie or response body
          let token = "";
          const setCookie = data.headers?.["set-cookie"] || "";
          const cookieMatch = setCookie.match(new RegExp(`${tokenParam}=([^;\\s]+)`));
          if (cookieMatch) token = cookieMatch[1];
          else {
            try {
              const body = JSON.parse(data.body || "{}");
              token = body[tokenParam] || body.token || body.session || body.access_token || "";
            } catch {
              const m = (data.body || "").match(new RegExp(`"${tokenParam}":\\s*"([^"]+)"`));
              if (m) token = m[1];
            }
          }
          if (token) {
            collected.push({ token, length: token.length, entropy: calcEntropy(token), charSet: getCharSet(token) });
          }
        } catch { }
        setProgress(Math.round(((i + 1) / sampleCount) * 100));
        setSamples([...collected]);
      }
    } finally { setRunning(false); }
  };

  const avgEntropy = samples.length > 0 ? samples.reduce((s, t) => s + t.entropy, 0) / samples.length : 0;
  const uniqueTokens = new Set(samples.map(s => s.token)).size;
  const avgLen = samples.length > 0 ? Math.round(samples.reduce((s, t) => s + t.length, 0) / samples.length) : 0;
  const isWeak = avgEntropy < 3 || uniqueTokens < samples.length * 0.9;

  return (
    <Layout>
      <div className="space-y-4 animate-in fade-in duration-500">
        <header className="border-b border-primary/20 pb-3">
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <Shuffle className="w-5 h-5 text-primary"/> SEQUENCER
          </h1>
          <p className="text-[10px] font-mono text-muted-foreground mt-0.5">Token randomness analysis — detect weak session tokens</p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="cyber-box p-4 space-y-3">
            <label className="font-mono text-xs text-primary">CONFIGURATION</label>
            <div className="flex gap-2">
              <select value={method} onChange={e => setMethod(e.target.value)}
                className="bg-black/50 border border-primary/30 px-2 py-2 font-mono text-xs text-foreground focus:outline-none w-20">
                {["GET","POST"].map(m => <option key={m}>{m}</option>)}
              </select>
              <input value={url} onChange={e => setUrl(e.target.value)}
                className="flex-1 bg-black/50 border border-primary/30 px-3 py-2 font-mono text-sm text-foreground focus:outline-none focus:border-primary"
                placeholder="https://target.com/api/login"/>
            </div>
            <div>
              <label className="font-mono text-[10px] text-muted-foreground">REQUEST HEADERS (JSON)</label>
              <textarea value={headers} onChange={e => setHeaders(e.target.value)} rows={3}
                className="w-full bg-black/50 border border-primary/30 p-2 font-mono text-xs text-foreground focus:outline-none mt-1 resize-none"/>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="font-mono text-[10px] text-muted-foreground">TOKEN PARAMETER NAME</label>
                <input value={tokenParam} onChange={e => setTokenParam(e.target.value)}
                  className="w-full bg-black/50 border border-primary/30 px-2 py-2 font-mono text-xs text-foreground focus:outline-none mt-1"
                  placeholder="session, token, access_token"/>
              </div>
              <div>
                <label className="font-mono text-[10px] text-muted-foreground">SAMPLE COUNT</label>
                <input type="number" value={sampleCount} onChange={e => setSampleCount(Number(e.target.value))} min={10} max={200}
                  className="w-full bg-black/50 border border-primary/30 px-2 py-2 font-mono text-xs text-foreground focus:outline-none mt-1"/>
              </div>
            </div>
            <button onClick={run} disabled={running || !url}
              className="w-full cyber-button py-2.5 flex items-center justify-center gap-2">
              {running ? <><div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin"/>{progress}% — {samples.length} tokens collected</>
                : <><Play className="w-4 h-4"/>COLLECT {sampleCount} TOKENS</>}
            </button>
          </div>

          <div className="space-y-3">
            {samples.length > 0 && (
              <>
                <div className={cn("cyber-box p-4 border", isWeak ? "border-red-400/40 bg-red-400/5" : "border-primary/30 bg-primary/5")}>
                  <div className="flex items-center gap-2 mb-3">
                    {isWeak ? <AlertTriangle className="w-5 h-5 text-red-400"/> : <CheckCircle className="w-5 h-5 text-primary"/>}
                    <span className={cn("font-mono text-sm font-bold", isWeak ? "text-red-400" : "text-primary")}>
                      {isWeak ? "WEAK RANDOMNESS DETECTED" : "TOKENS APPEAR RANDOM"}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      { label: "SAMPLES", value: samples.length },
                      { label: "UNIQUE", value: `${uniqueTokens} (${Math.round(uniqueTokens/samples.length*100)}%)` },
                      { label: "AVG ENTROPY", value: `${avgEntropy.toFixed(2)} bits/char` },
                      { label: "AVG LENGTH", value: `${avgLen} chars` },
                      { label: "CHAR SET", value: samples[0]?.charSet || "—" },
                      { label: "COLLISIONS", value: samples.length - uniqueTokens },
                    ].map(({ label, value }) => (
                      <div key={label} className="p-2 border border-border/30">
                        <div className="font-mono text-[9px] text-muted-foreground">{label}</div>
                        <div className="font-mono text-xs text-foreground font-bold mt-0.5">{value}</div>
                      </div>
                    ))}
                  </div>
                  {isWeak && (
                    <div className="mt-3 font-mono text-[10px] text-red-400 border border-red-400/20 bg-red-400/5 p-2">
                      ⚠ Low entropy or token collisions detected. Tokens may be predictable — session hijacking risk.
                    </div>
                  )}
                </div>

                <div className="cyber-box p-3">
                  <div className="font-mono text-[10px] text-muted-foreground mb-2">SAMPLE TOKENS</div>
                  <div className="max-h-48 overflow-y-auto space-y-1">
                    {samples.slice(0, 20).map((s, i) => (
                      <div key={i} className="flex items-center justify-between font-mono text-[10px] py-1 border-b border-border/20">
                        <span className="text-primary truncate max-w-[200px]">{s.token}</span>
                        <span className="text-muted-foreground shrink-0 ml-2">{s.entropy.toFixed(1)}H · {s.length}c</span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
            {samples.length === 0 && !running && (
              <div className="cyber-box flex items-center justify-center" style={{minHeight:"300px"}}>
                <div className="text-center font-mono text-muted-foreground">
                  <Shuffle className="w-10 h-10 mx-auto mb-2 opacity-20"/>
                  <p className="text-sm">Configure endpoint → Collect tokens</p>
                  <p className="text-xs mt-1 opacity-60">Analyzes entropy and randomness</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
