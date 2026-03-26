import { useState } from "react";
import { Layout } from "@/components/layout";
import { GitCompare, Copy, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";

function diffWords(a: string, b: string) {
  const wa = a.split(/(\s+)/); const wb = b.split(/(\s+)/);
  const result: Array<{ text: string; type: "same"|"add"|"del" }> = [];
  let i = 0, j = 0;
  while (i < wa.length || j < wb.length) {
    if (i >= wa.length) { result.push({ text: wb[j++], type: "add" }); }
    else if (j >= wb.length) { result.push({ text: wa[i++], type: "del" }); }
    else if (wa[i] === wb[j]) { result.push({ text: wa[i], type: "same" }); i++; j++; }
    else { result.push({ text: wa[i++], type: "del" }); result.push({ text: wb[j++], type: "add" }); }
  }
  return result;
}

export default function ComparerPage() {
  const [left, setLeft] = useState(""); const [right, setRight] = useState("");
  const [mode, setMode] = useState<"words"|"bytes">("words");
  const [compared, setCompared] = useState(false);

  const diff = compared ? diffWords(left, right) : [];
  const added = diff.filter(d => d.type === "add").length;
  const deleted = diff.filter(d => d.type === "del").length;

  return (
    <Layout>
      <div className="space-y-4 animate-in fade-in duration-500">
        <header className="border-b border-primary/20 pb-3 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-display font-bold flex items-center gap-2">
              <GitCompare className="w-5 h-5 text-primary"/> COMPARER
            </h1>
            <p className="text-[10px] font-mono text-muted-foreground mt-0.5">Compare two responses — word diff or byte diff</p>
          </div>
          <div className="flex gap-2">
            <div className="flex border border-primary/30">
              {(["words","bytes"] as const).map(m => (
                <button key={m} onClick={() => setMode(m)}
                  className={cn("px-3 py-1.5 font-mono text-[10px] transition-all",
                    mode === m ? "bg-primary text-black" : "text-muted-foreground hover:text-primary")}>
                  {m.toUpperCase()}
                </button>
              ))}
            </div>
            <button onClick={() => setCompared(true)} className="cyber-button !py-1.5 !px-4 text-xs flex items-center gap-1.5">
              <GitCompare className="w-3.5 h-3.5"/> COMPARE
            </button>
          </div>
        </header>

        {compared && (
          <div className="flex gap-4 font-mono text-xs">
            <span className="text-primary">{diff.filter(d=>d.type==="same").length} same</span>
            <span className="text-green-400">+{added} added</span>
            <span className="text-red-400">-{deleted} deleted</span>
            <span className="text-muted-foreground">{Math.abs(left.length - right.length)} byte diff</span>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {[{ label: "RESPONSE A", val: left, set: setLeft }, { label: "RESPONSE B", val: right, set: setRight }].map(({ label, val, set }) => (
            <div key={label} className="cyber-box p-3 space-y-2">
              <div className="flex items-center justify-between">
                <label className="font-mono text-xs text-primary">{label}</label>
                <div className="flex gap-1">
                  <button onClick={() => navigator.clipboard.readText().then(t => set(t))}
                    className="font-mono text-[10px] text-muted-foreground hover:text-primary transition-colors flex items-center gap-1">
                    <Copy className="w-3 h-3"/> PASTE
                  </button>
                  <button onClick={() => set("")}
                    className="font-mono text-[10px] text-muted-foreground hover:text-red-400 transition-colors">CLEAR</button>
                </div>
              </div>
              <textarea value={val} onChange={e => { set(e.target.value); setCompared(false); }} rows={15}
                className="w-full bg-black/50 border border-primary/30 p-2 font-mono text-[10px] text-foreground focus:outline-none resize-none"
                placeholder="Paste HTTP response here..."/>
              <div className="font-mono text-[10px] text-muted-foreground">{val.length} bytes · {val.split("\n").length} lines</div>
            </div>
          ))}
        </div>

        {compared && diff.length > 0 && (
          <div className="cyber-box p-4">
            <h3 className="font-mono text-xs text-primary mb-3">DIFF VIEW</h3>
            <div className="bg-black/50 p-3 font-mono text-[11px] leading-relaxed max-h-96 overflow-auto border border-primary/10 break-all">
              {diff.map((d, i) => (
                <span key={i} className={cn(
                  d.type === "add" && "bg-green-500/30 text-green-300",
                  d.type === "del" && "bg-red-500/30 text-red-300 line-through",
                  d.type === "same" && "text-foreground/70"
                )}>{d.text}</span>
              ))}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
