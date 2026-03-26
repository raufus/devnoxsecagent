import { useParams } from "wouter";
import { useGetScanAiDecisions, useGetScan } from "@workspace/api-client-react";
import { Layout } from "@/components/layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Brain, Cpu, Target, CheckCircle, ArrowRight, Zap } from "lucide-react";
import { format } from "date-fns";
import { parseJsonField } from "@/lib/utils";

const PHASE_COLORS: Record<string, string> = {
  recon: "text-cyan-400 bg-cyan-400/10 border-cyan-400/30",
  ai_analysis: "text-purple-400 bg-purple-400/10 border-purple-400/30",
  exploitation: "text-red-400 bg-red-400/10 border-red-400/30",
  reporting: "text-green-400 bg-green-400/10 border-green-400/30",
};

const PRIORITY_COLOR: Record<number, string> = {
  1: "text-red-400",
  2: "text-orange-400",
  3: "text-yellow-400",
  4: "text-blue-400",
  5: "text-muted-foreground",
};

export default function AIBrainPage() {
  const { id } = useParams();
  const { data: scanData } = useGetScan(id!);
  const { data, isLoading } = useGetScanAiDecisions(id!);

  const decisions = data?.decisions || [];

  return (
    <Layout>
      <div className="flex flex-col gap-4 animate-in fade-in duration-500">
        <header className="flex items-center justify-between border-b border-primary/20 pb-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono mb-1">
              <span className="text-muted-foreground">TARGET:</span>
              <span className="text-cyan-400 px-2 py-0.5 bg-cyan-400/10 border border-cyan-400/30 truncate max-w-xs text-xs">
                {scanData?.targetUrl || "—"}
              </span>
            </div>
            <h1 className="text-2xl font-display font-bold">AI_ORCHESTRATOR</h1>
            <p className="text-xs font-mono text-muted-foreground mt-1">DECISION ENGINE • ATTACK STRATEGY • THREAT CORRELATION</p>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs text-primary">
            <Brain className="w-5 h-5 animate-pulse" />
            AI_BRAIN_v2
          </div>
        </header>

        {isLoading && (
          <div className="flex items-center gap-3 p-8 justify-center font-mono text-sm text-muted-foreground">
            <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            LOADING AI DECISIONS...
          </div>
        )}

        {!isLoading && decisions.length === 0 && (
          <div className="p-8 text-center">
            <Cpu className="w-12 h-12 text-muted-foreground mx-auto mb-3 opacity-40" />
            <p className="font-mono text-sm text-muted-foreground">No AI decisions recorded yet.</p>
            <p className="font-mono text-xs text-muted-foreground mt-1">Start a scan to see the AI orchestrator in action.</p>
          </div>
        )}

        {decisions.length > 0 && (
          <div className="space-y-4">
            {/* Summary bar */}
            <div className="grid grid-cols-3 gap-3">
              <Card className="border-primary/20 bg-card/50 p-3 text-center">
                <div className="text-2xl font-display font-bold text-primary">{decisions.length}</div>
                <div className="text-[10px] font-mono text-muted-foreground mt-0.5">DECISIONS MADE</div>
              </Card>
              <Card className="border-primary/20 bg-card/50 p-3 text-center">
                <div className="text-2xl font-display font-bold text-cyan-400">
                  {Math.round(decisions.reduce((a, d) => a + (d.confidence || 0), 0) / decisions.length)}%
                </div>
                <div className="text-[10px] font-mono text-muted-foreground mt-0.5">AVG CONFIDENCE</div>
              </Card>
              <Card className="border-primary/20 bg-card/50 p-3 text-center">
                <div className="text-2xl font-display font-bold text-purple-400">
                  {decisions.reduce((a, d) => a + parseJsonField<Array<{action: string; priority: number; reason: string}>>(d.actions, []).length, 0)}
                </div>
                <div className="text-[10px] font-mono text-muted-foreground mt-0.5">ACTIONS PLANNED</div>
              </Card>
            </div>

            {/* Decision cards */}
            <div className="space-y-4">
              {decisions.map((decision, idx) => {
                const actions = parseJsonField<Array<{action: string; priority: number; reason: string}>>(decision.actions, []);
                return (
                  <Card key={decision.id} className="border-primary/20 bg-card/50 backdrop-blur-sm">
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm font-mono flex items-center gap-2">
                          <Brain className="w-4 h-4 text-primary" />
                          <span className="text-muted-foreground">Decision #{idx + 1}</span>
                          <Badge className={`text-[10px] ${PHASE_COLORS[decision.phase] || "text-muted-foreground"}`}>
                            {decision.phase?.toUpperCase()}
                          </Badge>
                        </CardTitle>
                        <div className="flex items-center gap-2">
                          <div className="text-xs font-mono text-muted-foreground">CONFIDENCE:</div>
                          <div className={`text-sm font-display font-bold ${(decision.confidence || 0) >= 80 ? "text-green-400" : (decision.confidence || 0) >= 60 ? "text-yellow-400" : "text-red-400"}`}>
                            {decision.confidence || 0}%
                          </div>
                        </div>
                      </div>
                      <div className="text-[10px] font-mono text-muted-foreground">
                        {decision.createdAt ? format(new Date(decision.createdAt), "HH:mm:ss") : ""}
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {/* Reasoning */}
                      <div className="p-3 border border-cyan-400/20 bg-cyan-400/5 rounded">
                        <div className="text-[10px] font-mono text-cyan-400 mb-1 flex items-center gap-1">
                          <Zap className="w-3 h-3" />
                          AI REASONING
                        </div>
                        <p className="text-xs font-mono text-muted-foreground leading-relaxed">{decision.reasoning}</p>
                      </div>

                      {/* Decision */}
                      <div className="p-3 border border-primary/20 bg-primary/5 rounded">
                        <div className="text-[10px] font-mono text-primary mb-1 flex items-center gap-1">
                          <Target className="w-3 h-3" />
                          STRATEGIC DECISION
                        </div>
                        <p className="text-xs font-mono text-foreground leading-relaxed">{decision.decision}</p>
                      </div>

                      {/* Actions */}
                      {actions.length > 0 && (
                        <div>
                          <div className="text-[10px] font-mono text-muted-foreground mb-2 flex items-center gap-1">
                            <CheckCircle className="w-3 h-3" />
                            ATTACK ACTIONS ({actions.length})
                          </div>
                          <div className="space-y-1">
                            {actions.map((action, i) => (
                              <div key={i} className="flex items-start gap-3 p-2 border border-primary/10 bg-background/50 rounded">
                                <div className={`text-xs font-display font-bold shrink-0 ${PRIORITY_COLOR[action.priority] || "text-muted-foreground"}`}>
                                  P{action.priority}
                                </div>
                                <ArrowRight className="w-3 h-3 text-primary/40 mt-0.5 shrink-0" />
                                <div>
                                  <div className="text-xs font-mono text-foreground">{action.action}</div>
                                  {action.reason && <div className="text-[10px] font-mono text-muted-foreground mt-0.5">{action.reason}</div>}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
