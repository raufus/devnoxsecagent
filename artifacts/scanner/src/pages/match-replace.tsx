import { useState } from "react";
import { Layout } from "@/components/layout";
import { Replace, Plus, Trash2, ToggleLeft, ToggleRight, Play } from "lucide-react";
import { cn } from "@/lib/utils";

interface Rule {
  id: string; enabled: boolean; type: "request"|"response";
  match: string; replace: string; isRegex: boolean; comment: string;
}

const STORAGE_KEY = "devnox_match_replace_rules";

function loadRules(): Rule[] {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); } catch { return []; }
}

function saveRules(rules: Rule[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(rules));
}

export default function MatchReplacePage() {
  const [rules, setRules] = useState<Rule[]>(loadRules);
  const [testInput, setTestInput] = useState("");
  const [testOutput, setTestOutput] = useState("");
  const [testType, setTestType] = useState<"request"|"response">("request");

  const addRule = () => {
    const r: Rule = { id: crypto.randomUUID(), enabled: true, type: "request", match: "", replace: "", isRegex: false, comment: "" };
    const updated = [...rules, r];
    setRules(updated); saveRules(updated);
  };

  const updateRule = (id: string, changes: Partial<Rule>) => {
    const updated = rules.map(r => r.id === id ? { ...r, ...changes } : r);
    setRules(updated); saveRules(updated);
  };

  const deleteRule = (id: string) => {
    const updated = rules.filter(r => r.id !== id);
    setRules(updated); saveRules(updated);
  };

  const applyRules = () => {
    let output = testInput;
    for (const rule of rules.filter(r => r.enabled && r.type === testType && r.match)) {
      try {
        if (rule.isRegex) {
          output = output.replace(new RegExp(rule.match, "g"), rule.replace);
        } else {
          output = output.split(rule.match).join(rule.replace);
        }
      } catch { }
    }
    setTestOutput(output);
  };

  return (
    <Layout>
      <div className="space-y-4 animate-in fade-in duration-500">
        <header className="border-b border-primary/20 pb-3 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-display font-bold flex items-center gap-2">
              <Replace className="w-5 h-5 text-primary" /> MATCH & REPLACE
            </h1>
            <p className="text-[10px] font-mono text-muted-foreground mt-0.5">Auto-modify requests/responses — regex or literal match</p>
          </div>
          <button onClick={addRule} className="cyber-button !py-1.5 !px-3 text-xs flex items-center gap-1.5">
            <Plus className="w-3.5 h-3.5" /> ADD RULE
          </button>
        </header>

        {/* Rules */}
        <div className="space-y-2">
          {rules.length === 0 ? (
            <div className="cyber-box p-8 text-center font-mono text-xs text-muted-foreground">
              <Replace className="w-8 h-8 mx-auto mb-2 opacity-20" />
              No rules yet — click ADD RULE to create one
            </div>
          ) : rules.map(rule => (
            <div key={rule.id} className={cn("cyber-box p-3 border transition-all", rule.enabled ? "border-primary/20" : "border-border/20 opacity-60")}>
              <div className="flex items-center gap-2 flex-wrap">
                <button onClick={() => updateRule(rule.id, { enabled: !rule.enabled })} className="shrink-0">
                  {rule.enabled
                    ? <ToggleRight className="w-5 h-5 text-primary" />
                    : <ToggleLeft className="w-5 h-5 text-muted-foreground" />}
                </button>
                <select value={rule.type} onChange={e => updateRule(rule.id, { type: e.target.value as "request"|"response" })}
                  className="bg-black/50 border border-primary/30 px-2 py-1 font-mono text-[10px] text-foreground focus:outline-none">
                  <option value="request">REQUEST</option>
                  <option value="response">RESPONSE</option>
                </select>
                <label className="flex items-center gap-1 font-mono text-[10px] text-muted-foreground cursor-pointer">
                  <input type="checkbox" checked={rule.isRegex} onChange={e => updateRule(rule.id, { isRegex: e.target.checked })} className="accent-primary" />
                  REGEX
                </label>
                <input value={rule.match} onChange={e => updateRule(rule.id, { match: e.target.value })}
                  className="flex-1 min-w-24 bg-black/50 border border-red-400/30 px-2 py-1 font-mono text-[10px] text-red-300 focus:outline-none focus:border-red-400"
                  placeholder="Match pattern..." />
                <span className="font-mono text-[10px] text-muted-foreground">→</span>
                <input value={rule.replace} onChange={e => updateRule(rule.id, { replace: e.target.value })}
                  className="flex-1 min-w-24 bg-black/50 border border-green-400/30 px-2 py-1 font-mono text-[10px] text-green-300 focus:outline-none focus:border-green-400"
                  placeholder="Replace with..." />
                <input value={rule.comment} onChange={e => updateRule(rule.id, { comment: e.target.value })}
                  className="w-32 bg-black/50 border border-border/30 px-2 py-1 font-mono text-[10px] text-muted-foreground focus:outline-none"
                  placeholder="Comment..." />
                <button onClick={() => deleteRule(rule.id)} className="text-red-400/60 hover:text-red-400 transition-colors shrink-0">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Test Area */}
        <div className="cyber-box p-4 space-y-3">
          <div className="flex items-center justify-between">
            <label className="font-mono text-xs text-primary">TEST RULES</label>
            <div className="flex gap-2">
              <div className="flex border border-primary/30">
                {(["request","response"] as const).map(t => (
                  <button key={t} onClick={() => setTestType(t)}
                    className={cn("px-3 py-1 font-mono text-[10px] transition-all",
                      testType === t ? "bg-primary text-black" : "text-muted-foreground hover:text-primary")}>
                    {t.toUpperCase()}
                  </button>
                ))}
              </div>
              <button onClick={applyRules} className="cyber-button !py-1 !px-3 text-[10px] flex items-center gap-1">
                <Play className="w-3 h-3" /> APPLY
              </button>
            </div>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <div>
              <label className="font-mono text-[10px] text-muted-foreground">INPUT</label>
              <textarea value={testInput} onChange={e => setTestInput(e.target.value)} rows={8}
                className="w-full bg-black/50 border border-primary/30 p-2 font-mono text-[10px] text-foreground focus:outline-none mt-1 resize-none"
                placeholder="Paste request/response to test rules..." />
            </div>
            <div>
              <label className="font-mono text-[10px] text-muted-foreground">OUTPUT (after rules applied)</label>
              <pre className="w-full bg-black/50 border border-primary/10 p-2 font-mono text-[10px] text-green-300 mt-1 min-h-[160px] overflow-auto whitespace-pre-wrap break-all">
                {testOutput || "(click APPLY to see result)"}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
