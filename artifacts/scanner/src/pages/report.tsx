import { useGetScanReport } from "@workspace/api-client-react";
import { Layout } from "@/components/layout";
import { useParams, Link } from "wouter";
import {
  ShieldAlert, Download, Bug, ChevronLeft, Target, Terminal,
  AlertTriangle, Info, CheckCircle, Globe, Lock, Eye, Server, Brain, Network, Zap
} from "lucide-react";
import { getSeverityColor, parseJsonField } from "@/lib/utils";
import { format } from "date-fns";
import { cn } from "@/lib/utils";
import { useState } from "react";

type Severity = "critical" | "high" | "medium" | "low" | "info";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEV_CONFIG: Record<Severity, { label: string; color: string; icon: any; bg: string }> = {
  critical: { label: "CRITICAL", color: "text-red-500", icon: AlertTriangle, bg: "bg-red-500/10 border-red-500/30" },
  high: { label: "HIGH", color: "text-orange-500", icon: AlertTriangle, bg: "bg-orange-500/10 border-orange-500/30" },
  medium: { label: "MEDIUM", color: "text-yellow-500", icon: AlertTriangle, bg: "bg-yellow-500/10 border-yellow-500/30" },
  low: { label: "LOW", color: "text-cyan-500", icon: Info, bg: "bg-cyan-500/10 border-cyan-500/30" },
  info: { label: "INFO", color: "text-gray-400", icon: Info, bg: "bg-gray-500/10 border-gray-500/30" },
};

const TYPE_ICONS: Record<string, any> = {
  "XSS": Globe,
  "SQLi": Server,
  "SSRF": Globe,
  "CSRF": Lock,
  "IDOR": Eye,
  "XXE": Server,
  "CORS": Globe,
  "Command Injection": Terminal,
  "Path Traversal": Server,
  "SSL/TLS": Lock,
  "Security Header": Lock,
  "Cookie Security": Lock,
  "Information Disclosure": Eye,
  "Sensitive File Exposure": Eye,
  "Open Redirect": Globe,
  "Auth": Lock,
  "HTTP Methods": Globe,
};

function getRiskColor(score: number) {
  if (score >= 80) return "text-red-500";
  if (score >= 60) return "text-orange-500";
  if (score >= 40) return "text-yellow-500";
  return "text-primary";
}

export default function Report() {
  const { id } = useParams();
  const { data, isLoading, error } = useGetScanReport(id!);
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState(false);

  if (isLoading)
    return <Layout><div className="text-primary font-mono text-center py-20 animate-pulse text-sm">GENERATING_REPORT...</div></Layout>;
  if (error || !data)
    return <Layout><div className="text-red-500 font-mono text-center py-20 text-sm">ERR: REPORT_NOT_FOUND</div></Layout>;

  const { scan, findings, riskScore } = data;

  const filtered = filter === "all"
    ? [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity as Severity) - SEV_ORDER.indexOf(b.severity as Severity))
    : findings.filter(f => f.severity === filter);

  const byType = findings.reduce((acc, f) => {
    acc[f.type] = (acc[f.type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const handlePDF = async () => {
    setIsExporting(true);
    try {
      console.log("Starting PDF generation...");
      const jsPDF = (await import("jspdf")).default;
      console.log("jsPDF loaded:", jsPDF);
      const autoTable = (await import("jspdf-autotable")).default;
      console.log("autoTable loaded:", autoTable);

      const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
      const pageW = doc.internal.pageSize.getWidth();

      const PRIMARY = [0, 255, 128] as [number, number, number];
      const DARK = [10, 10, 10] as [number, number, number];
      const GRAY = [100, 100, 100] as [number, number, number];
      const WHITE = [255, 255, 255] as [number, number, number];
      const RED = [220, 50, 50] as [number, number, number];
      const ORANGE = [255, 140, 0] as [number, number, number];
      const YELLOW = [230, 200, 0] as [number, number, number];
      const CYAN = [0, 200, 220] as [number, number, number];

      const sevColor = (sev: string): [number, number, number] => {
        if (sev === "critical") return RED;
        if (sev === "high") return ORANGE;
        if (sev === "medium") return YELLOW;
        if (sev === "low") return CYAN;
        return GRAY;
      };

      // Cover Page
      doc.setFillColor(...DARK);
      doc.rect(0, 0, pageW, 297, "F");

      doc.setFillColor(...PRIMARY);
      doc.rect(0, 0, pageW, 2, "F");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(28);
      doc.setTextColor(...PRIMARY);
      doc.text("DEVNOX SEC AGENT", pageW / 2, 50, { align: "center" });

      doc.setFontSize(14);
      doc.setTextColor(...WHITE);
      doc.text("AUTONOMOUS PENETRATION TEST REPORT", pageW / 2, 62, { align: "center" });

      doc.setFillColor(...PRIMARY);
      doc.rect(20, 70, pageW - 40, 0.5, "F");

      doc.setFontSize(10);
      doc.setTextColor(...GRAY);
      doc.text("TARGET", 20, 85);
      doc.setTextColor(...WHITE);
      doc.setFont("helvetica", "normal");
      doc.text(scan.targetUrl, 20, 91);

      doc.setTextColor(...GRAY);
      doc.setFont("helvetica", "bold");
      doc.text("SCAN DATE", 20, 102);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(...WHITE);
      doc.text(format(new Date(data.generatedAt), "yyyy-MM-dd HH:mm 'UTC'"), 20, 108);

      doc.setTextColor(...GRAY);
      doc.setFont("helvetica", "bold");
      doc.text("SCAN MODE", 20, 119);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(...WHITE);
      doc.text(scan.scanType.toUpperCase(), 20, 125);

      doc.setTextColor(...GRAY);
      doc.setFont("helvetica", "bold");
      doc.text("SCAN ID", 20, 136);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(...WHITE);
      doc.text(scan.id, 20, 142);

      // Risk Score
      const riskColor = riskScore >= 80 ? RED : riskScore >= 60 ? ORANGE : riskScore >= 40 ? YELLOW : PRIMARY;
      const boxX = pageW - 70;
      doc.setFillColor(riskColor[0] / 5, riskColor[1] / 5, riskColor[2] / 5);
      doc.rect(boxX, 80, 55, 55, "F");
      doc.setDrawColor(...riskColor);
      doc.setLineWidth(0.5);
      doc.rect(boxX, 80, 55, 55, "S");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      doc.setTextColor(...riskColor);
      doc.text("RISK SCORE", boxX + 27.5, 90, { align: "center" });
      doc.setFontSize(36);
      doc.text(riskScore.toFixed(0), boxX + 27.5, 112, { align: "center" });
      doc.setFontSize(9);
      doc.setTextColor(...GRAY);
      doc.text("/ 100", boxX + 27.5, 122, { align: "center" });

      // Summary stats
      doc.setFillColor(20, 20, 20);
      doc.rect(20, 160, pageW - 40, 55, "F");
      doc.setDrawColor(...PRIMARY);
      doc.setLineWidth(0.3);
      doc.rect(20, 160, pageW - 40, 55, "S");

      const metrics = [
        { label: "CRITICAL", count: scan.criticalCount, color: RED },
        { label: "HIGH", count: scan.highCount, color: ORANGE },
        { label: "MEDIUM", count: scan.mediumCount, color: YELLOW },
        { label: "LOW", count: scan.lowCount, color: CYAN },
        { label: "INFO", count: scan.infoCount, color: GRAY },
        { label: "TOTAL", count: scan.totalFindings, color: PRIMARY },
      ];
      const cellW = (pageW - 40) / metrics.length;
      metrics.forEach((m, i) => {
        const cx = 20 + i * cellW + cellW / 2;
        doc.setFont("helvetica", "bold");
        doc.setFontSize(20);
        doc.setTextColor(...m.color);
        doc.text(String(m.count), cx, 185, { align: "center" });
        doc.setFontSize(7);
        doc.setTextColor(...GRAY);
        doc.text(m.label, cx, 194, { align: "center" });
      });

      // Tech stack
      if (scan.techStack && parseJsonField<string[]>(scan.techStack, []).length > 0) {
        doc.setFont("helvetica", "bold");
        doc.setFontSize(8);
        doc.setTextColor(...PRIMARY);
        doc.text("TECHNOLOGY STACK:", 20, 228);
        doc.setFont("helvetica", "normal");
        doc.setTextColor(...WHITE);
        doc.text(parseJsonField<string[]>(scan.techStack, []).join("  ·  "), 20, 234);
      }

      doc.setFillColor(...PRIMARY);
      doc.rect(0, 293, pageW, 4, "F");
      doc.setFont("helvetica", "normal");
      doc.setFontSize(7);
      doc.setTextColor(...GRAY);
      doc.text("CONFIDENTIAL — DEVNOX SEC AGENT — Autonomous Penetration Test Report", pageW / 2, 291, { align: "center" });

      // Page 2: Findings
      doc.addPage();
      doc.setFillColor(...DARK);
      doc.rect(0, 0, pageW, 297, "F");
      doc.setFillColor(...PRIMARY);
      doc.rect(0, 0, pageW, 2, "F");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(16);
      doc.setTextColor(...PRIMARY);
      doc.text("VULNERABILITY FINDINGS", 20, 20);
      doc.setFontSize(9);
      doc.setTextColor(...GRAY);
      doc.text(`${findings.length} finding(s) discovered`, 20, 27);

      autoTable(doc, {
        startY: 33,
        head: [["#", "SEVERITY", "TYPE", "TITLE", "ENDPOINT", "CVSS"]],
        body: [...findings]
          .sort((a, b) => SEV_ORDER.indexOf(a.severity as Severity) - SEV_ORDER.indexOf(b.severity as Severity))
          .map((f, i) => [
            String(i + 1),
            f.severity.toUpperCase(),
            f.type,
            f.title.length > 45 ? f.title.substring(0, 42) + "..." : f.title,
            (f.endpoint || "").length > 40 ? (f.endpoint || "").substring(0, 37) + "..." : (f.endpoint || ""),
            f.cvssScore ? String(f.cvssScore) : "-",
          ]),
        headStyles: {
          fillColor: [15, 15, 15],
          textColor: [0, 255, 128],
          fontStyle: "bold",
          fontSize: 7,
          halign: "left",
        },
        bodyStyles: {
          fillColor: [10, 10, 10],
          textColor: [200, 200, 200],
          fontSize: 7,
          lineColor: [30, 30, 30],
          lineWidth: 0.2,
        },
        alternateRowStyles: { fillColor: [15, 15, 15] },
        didParseCell: (data) => {
          if (data.column.index === 1 && data.section === "body") {
            const sev = data.cell.raw as string;
            const color = sev === "CRITICAL" ? RED : sev === "HIGH" ? ORANGE : sev === "MEDIUM" ? YELLOW : sev === "LOW" ? CYAN : GRAY;
            data.cell.styles.textColor = color;
            data.cell.styles.fontStyle = "bold";
          }
        },
        columnStyles: {
          0: { cellWidth: 8 },
          1: { cellWidth: 20 },
          2: { cellWidth: 25 },
          3: { cellWidth: 70 },
          4: { cellWidth: 45 },
          5: { cellWidth: 12 },
        },
        margin: { left: 20, right: 20 },
      });

      // Detailed findings pages
      for (const finding of findings.sort((a, b) => SEV_ORDER.indexOf(a.severity as Severity) - SEV_ORDER.indexOf(b.severity as Severity))) {
        doc.addPage();
        doc.setFillColor(...DARK);
        doc.rect(0, 0, pageW, 297, "F");

        const sev = finding.severity as Severity;
        const sc = sevColor(sev);
        doc.setFillColor(sc[0] / 8, sc[1] / 8, sc[2] / 8);
        doc.rect(0, 0, pageW, 18, "F");
        doc.setFillColor(...sc);
        doc.rect(0, 0, 4, 18, "F");

        doc.setFont("helvetica", "bold");
        doc.setFontSize(7);
        doc.setTextColor(...sc);
        doc.text(finding.severity.toUpperCase(), 10, 8);
        doc.setFontSize(10);
        doc.setTextColor(...WHITE);
        const title = finding.title.length > 70 ? finding.title.substring(0, 67) + "..." : finding.title;
        doc.text(title, 10, 14);

        if (finding.cvssScore) {
          doc.setFont("helvetica", "bold");
          doc.setFontSize(8);
          doc.setTextColor(...sc);
          doc.text(`CVSS ${finding.cvssScore}`, pageW - 20, 8, { align: "right" });
        }
        doc.setFont("helvetica", "bold");
        doc.setFontSize(7);
        doc.setTextColor(0, 255, 128);
        doc.text(finding.type, pageW - 20, 14, { align: "right" });

        let y = 26;
        const section = (label: string, val: string, color?: [number, number, number]) => {
          if (!val) return;
          doc.setFont("helvetica", "bold");
          doc.setFontSize(7);
          doc.setTextColor(...(color || GRAY));
          doc.text(label, 20, y);
          y += 4;
          doc.setFont("helvetica", "normal");
          doc.setTextColor(...WHITE);
          doc.setFontSize(8);
          const lines = doc.splitTextToSize(val, pageW - 40);
          doc.text(lines, 20, y);
          y += lines.length * 4 + 3;
        };

        const box = (label: string, val: string, bColor?: [number, number, number]) => {
          if (!val) return;
          doc.setFont("helvetica", "bold");
          doc.setFontSize(7);
          doc.setTextColor(...(bColor || GRAY));
          doc.text(label, 20, y);
          y += 4;
          doc.setFillColor(15, 15, 15);
          const lines = doc.splitTextToSize(val, pageW - 48);
          const h = lines.length * 4 + 6;
          doc.rect(20, y - 2, pageW - 40, h, "F");
          doc.setFont("courier", "normal");
          doc.setFontSize(7);
          doc.setTextColor(...WHITE);
          doc.text(lines, 24, y + 2);
          y += h + 4;
        };

        section("DESCRIPTION", finding.description || "");
        if (finding.endpoint) section("AFFECTED ENDPOINT", `${finding.method || "GET"} ${finding.endpoint}`, CYAN);
        if (finding.parameter) section("VULNERABLE PARAMETER", finding.parameter, RED);
        if (finding.payload) box("INJECTED PAYLOAD", finding.payload, RED);
        if (finding.evidence) box("EVIDENCE", finding.evidence, YELLOW);
        if (finding.aiAnalysis) {
          doc.setFont("helvetica", "bold");
          doc.setFontSize(7);
          doc.setTextColor(...PRIMARY);
          doc.text("AI ANALYSIS", 20, y);
          y += 4;
          doc.setFillColor(0, 30, 15);
          const lines = doc.splitTextToSize(finding.aiAnalysis, pageW - 48);
          const h = lines.length * 4 + 6;
          doc.rect(20, y - 2, pageW - 40, h, "F");
          doc.setFont("helvetica", "normal");
          doc.setFontSize(8);
          doc.setTextColor(...PRIMARY);
          doc.text(lines, 24, y + 2);
          y += h + 4;
        }
        if (finding.recommendation) section("REMEDIATION", finding.recommendation, [0, 200, 100]);
        if (finding.cweId) section("CWE REFERENCE", finding.cweId, GRAY);

        doc.setFillColor(...PRIMARY);
        doc.rect(0, 293, pageW, 1, "F");
        doc.setFont("helvetica", "normal");
        doc.setFontSize(6);
        doc.setTextColor(...GRAY);
        doc.text("DEVNOX SEC AGENT — Confidential", pageW / 2, 291, { align: "center" });
      }

      // AI Summary page
      if (scan.aiAnalysis) {
        doc.addPage();
        doc.setFillColor(...DARK);
        doc.rect(0, 0, pageW, 297, "F");
        doc.setFillColor(...PRIMARY);
        doc.rect(0, 0, pageW, 2, "F");
        doc.setFont("helvetica", "bold");
        doc.setFontSize(14);
        doc.setTextColor(...PRIMARY);
        doc.text("AI SECURITY ANALYSIS", 20, 18);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(8);
        doc.setTextColor(200, 200, 200);
        const lines = doc.splitTextToSize(scan.aiAnalysis, pageW - 40);
        doc.text(lines, 20, 28);
      }

      const filename = `devnox_report_${scan.id.split("-")[0]}_${format(new Date(), "yyyyMMdd_HHmm")}.pdf`;
      doc.save(filename);
    } catch (err) {
      console.error("PDF export failed:", err);
      alert(`PDF generation failed: ${err instanceof Error ? err.message : String(err)}\n\nPlease check browser console for details.`);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `devnox_report_${scan.id.split("-")[0]}.json`;
    a.click();
  };

  return (
    <Layout>
      <div className="space-y-5 animate-in fade-in duration-500 pb-20 lg:pb-6">
        {/* Top Nav */}
        <div className="flex items-center justify-between">
          <Link href={`/scans/${id}/live`} className="text-muted-foreground hover:text-primary font-mono text-xs flex items-center gap-1 transition-colors">
            <ChevronLeft className="w-4 h-4" /> BACK
          </Link>
          <div className="flex flex-wrap gap-2 justify-end">
            <Link href={`/scans/${id}/advanced`} className="cyber-button !py-1.5 !px-3 text-xs flex items-center gap-1.5 !border-primary/40 !text-primary hover:!border-primary hover:!bg-primary/10">
              <Zap className="w-3 h-3" /> ADVANCED
            </Link>
            <Link href={`/scans/${id}/recon`} className="cyber-button !py-1.5 !px-3 text-xs flex items-center gap-1.5 !border-cyan-400/40 !text-cyan-400 hover:!border-cyan-400 hover:!bg-cyan-400/10">
              <Globe className="w-3 h-3" /> RECON
            </Link>
            <Link href={`/scans/${id}/ai-brain`} className="cyber-button !py-1.5 !px-3 text-xs flex items-center gap-1.5 !border-purple-400/40 !text-purple-400 hover:!border-purple-400 hover:!bg-purple-400/10">
              <Brain className="w-3 h-3" /> AI BRAIN
            </Link>
            <Link href={`/scans/${id}/graph`} className="cyber-button !py-1.5 !px-3 text-xs flex items-center gap-1.5 !border-orange-400/40 !text-orange-400 hover:!border-orange-400 hover:!bg-orange-400/10">
              <Network className="w-3 h-3" /> GRAPH
            </Link>
            <Link href={`/scans/${id}/exploit`} className="cyber-button !py-1.5 !px-3 text-xs flex items-center gap-1.5 !border-red-400/40 !text-red-400 hover:!border-red-400 hover:!bg-red-400/10">
              <Zap className="w-3 h-3" /> EXPLOIT
            </Link>
            <button onClick={handleExportJSON} className="cyber-button !py-1.5 !px-3 text-xs flex items-center gap-1.5 !border-muted-foreground/40 !text-muted-foreground hover:!border-primary hover:!text-primary">
              <Download className="w-3 h-3" /> JSON
            </button>
            <button onClick={handlePDF} disabled={isExporting} className="cyber-button !py-1.5 !px-3 text-xs flex items-center gap-1.5">
              <Download className="w-3.5 h-3.5" />
              {isExporting ? "GENERATING..." : "PDF REPORT"}
            </button>
          </div>
        </div>

        {/* Report Header */}
        <div className="cyber-box p-4 sm:p-6 border-t-4 border-t-primary relative overflow-hidden">
          <ShieldAlert className="absolute -right-6 -bottom-6 w-40 h-40 text-primary/5 pointer-events-none hidden sm:block" />
          <div className="flex flex-col sm:flex-row justify-between items-start gap-4">
            <div className="flex-1 min-w-0">
              <div className="font-mono text-[10px] text-primary mb-1">DEVNOX SEC AGENT — AUTONOMOUS PENETRATION TEST REPORT</div>
              <h1 className="text-xl sm:text-2xl font-display font-bold text-foreground">
                Security Assessment Report
              </h1>
              <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] sm:text-xs mt-2 text-muted-foreground">
                <span className="flex items-center gap-1.5 text-cyan-400">
                  <Target className="w-3 h-3 shrink-0" />
                  <span className="break-all">{scan.targetUrl}</span>
                </span>
                <span>{format(new Date(data.generatedAt), "yyyy-MM-dd HH:mm 'UTC'")}</span>
                <span className="uppercase">MODE: {scan.scanType}</span>
                <span>ID: {scan.id.split("-")[0].toUpperCase()}</span>
              </div>
              {scan.techStack && parseJsonField<string[]>(scan.techStack, []).length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {parseJsonField<string[]>(scan.techStack, []).map(t => (
                    <span key={t} className="px-1.5 py-0.5 bg-primary/10 border border-primary/20 font-mono text-[9px] text-primary/70">{t}</span>
                  ))}
                </div>
              )}
            </div>

            <div className="flex flex-col items-center p-3 sm:p-4 border min-w-[100px] shrink-0" style={{ borderColor: riskScore >= 80 ? "#dc3232" : riskScore >= 60 ? "#ff8c00" : riskScore >= 40 ? "#e6c800" : "#00ff80" }}>
              <span className="font-mono text-[10px] text-muted-foreground mb-1">RISK_SCORE</span>
              <span className={cn("text-4xl sm:text-5xl font-display font-bold", getRiskColor(riskScore))}>
                {riskScore.toFixed(0)}
              </span>
              <span className="text-[10px] font-mono text-muted-foreground mt-0.5">/ 100</span>
            </div>
          </div>

          {/* Severity Metrics */}
          <div className="mt-4 pt-4 border-t border-border grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div>
              <h3 className="text-primary font-mono text-[10px] mb-2">AI_EXECUTIVE_SUMMARY</h3>
              <div className="bg-black/40 border border-primary/20 p-3 text-xs text-foreground/80 leading-relaxed max-h-28 overflow-y-auto font-mono whitespace-pre-line">
                {scan.aiAnalysis ? scan.aiAnalysis.split("\n").slice(0, 8).join("\n") : "Analysis not available."}
              </div>
            </div>
            <div>
              <h3 className="text-primary font-mono text-[10px] mb-2">THREAT_METRICS</h3>
              <div className="grid grid-cols-5 gap-1">
                {[
                  { label: "CRITICAL", count: scan.criticalCount, c: "text-red-500 border-red-500/30 bg-red-500/10" },
                  { label: "HIGH", count: scan.highCount, c: "text-orange-500 border-orange-500/30 bg-orange-500/10" },
                  { label: "MED", count: scan.mediumCount, c: "text-yellow-500 border-yellow-500/30 bg-yellow-500/10" },
                  { label: "LOW", count: scan.lowCount, c: "text-cyan-500 border-cyan-500/30 bg-cyan-500/10" },
                  { label: "INFO", count: scan.infoCount, c: "text-gray-400 border-gray-500/30 bg-gray-500/10" },
                ].map(({ label, count, c }) => (
                  <div key={label} className={cn("flex flex-col items-center justify-center p-2 border", c)}>
                    <span className="font-display text-xl font-bold">{count}</span>
                    <span className="text-[8px] font-mono mt-0.5 text-center leading-tight">{label}</span>
                  </div>
                ))}
              </div>

              {/* Vuln type breakdown */}
              {Object.keys(byType).length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {Object.entries(byType).sort(([, a], [, b]) => b - a).map(([type, count]) => {
                    const Icon = TYPE_ICONS[type] || Bug;
                    return (
                      <span key={type} className="flex items-center gap-1 px-1.5 py-0.5 border border-border/50 bg-white/5 font-mono text-[9px] text-muted-foreground">
                        <Icon className="w-2.5 h-2.5" /> {type} ({count})
                      </span>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Findings Section */}
        <div>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <h2 className="text-lg sm:text-xl font-display text-primary flex items-center gap-2">
              <Bug className="w-5 h-5 shrink-0" /> FINDINGS ({findings.length})
            </h2>
            {/* Filter pills */}
            <div className="flex gap-1 flex-wrap">
              {(["all", ...SEV_ORDER] as const).map(s => (
                <button
                  key={s}
                  onClick={() => setFilter(s)}
                  className={cn(
                    "px-2 py-0.5 font-mono text-[10px] border uppercase transition-all",
                    filter === s
                      ? s === "all" ? "border-primary bg-primary/20 text-primary" :
                        s === "critical" ? "border-red-500 bg-red-500/20 text-red-500" :
                          s === "high" ? "border-orange-500 bg-orange-500/20 text-orange-500" :
                            s === "medium" ? "border-yellow-500 bg-yellow-500/20 text-yellow-500" :
                              s === "low" ? "border-cyan-500 bg-cyan-500/20 text-cyan-500" :
                                "border-gray-500 bg-gray-500/20 text-gray-400"
                      : "border-border/50 text-muted-foreground hover:border-primary/30"
                  )}
                >
                  {s === "all" ? `ALL (${findings.length})` : `${s} (${findings.filter(f => f.severity === s).length})`}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            {filtered.length === 0 ? (
              <div className="cyber-box p-8 text-center font-mono text-muted-foreground border-dashed text-sm flex flex-col items-center gap-2">
                <CheckCircle className="w-8 h-8 text-primary/30" />
                {filter === "all" ? "NO VULNERABILITIES DETECTED — TARGET APPEARS SECURE" : `NO ${filter.toUpperCase()} FINDINGS`}
              </div>
            ) : (
              filtered.map((finding) => {
                const isExpanded = expandedId === finding.id;
                const sev = finding.severity as Severity;
                const cfg = SEV_CONFIG[sev];
                const Icon = TYPE_ICONS[finding.type] || Bug;
                return (
                  <div key={finding.id} className={cn("cyber-box p-0 overflow-hidden border", cfg.bg)}>
                    {/* Finding header — always visible, clickable */}
                    <button
                      className="w-full text-left p-3 sm:p-4 flex items-start justify-between gap-3 hover:bg-white/5 transition-colors"
                      onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                    >
                      <div className="flex items-start gap-3 min-w-0 flex-1">
                        <span className={cn("px-2 py-0.5 font-mono text-[10px] uppercase border shrink-0 mt-0.5", getSeverityColor(finding.severity))}>
                          {finding.severity}
                        </span>
                        <div className="min-w-0">
                          <h3 className="font-bold text-sm sm:text-base text-foreground leading-tight">{finding.title}</h3>
                          <div className="flex flex-wrap gap-1.5 mt-1">
                            <span className="font-mono text-[9px] text-muted-foreground px-1.5 py-0.5 border border-border/40 flex items-center gap-1">
                              <Icon className="w-2.5 h-2.5" /> {finding.type}
                            </span>
                            {finding.cvssScore && (
                              <span className="font-mono text-[9px] text-primary px-1.5 py-0.5 border border-primary/30">
                                CVSS {finding.cvssScore}
                              </span>
                            )}
                            {finding.cweId && (
                              <span className="font-mono text-[9px] text-muted-foreground px-1.5 py-0.5 border border-border/40">
                                {finding.cweId}
                              </span>
                            )}
                            {finding.endpoint && (
                              <span className="font-mono text-[9px] text-cyan-400/70 truncate max-w-[200px] sm:max-w-sm">
                                {finding.endpoint}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <span className="font-mono text-[10px] text-muted-foreground shrink-0 mt-1">
                        {isExpanded ? "▲ HIDE" : "▼ DETAIL"}
                      </span>
                    </button>

                    {/* Expanded body */}
                    {isExpanded && (
                      <div className="border-t border-border/30 p-4 sm:p-5 grid grid-cols-1 lg:grid-cols-3 gap-5">
                        <div className="lg:col-span-2 space-y-4">
                          <div>
                            <h4 className="font-mono text-[10px] text-muted-foreground mb-1.5">DESCRIPTION</h4>
                            <p className="text-xs sm:text-sm text-foreground/80 leading-relaxed">{finding.description}</p>
                          </div>

                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div className="p-3 border border-border/30 bg-black/20">
                              <h4 className="font-mono text-[10px] text-muted-foreground mb-1">ENDPOINT</h4>
                              <div className="font-mono text-[11px] text-cyan-400 break-all">
                                {finding.method || "GET"} {finding.endpoint}
                              </div>
                            </div>
                            {finding.parameter && (
                              <div className="p-3 border border-border/30 bg-black/20">
                                <h4 className="font-mono text-[10px] text-muted-foreground mb-1">VULNERABLE PARAMETER</h4>
                                <div className="font-mono text-[11px] text-red-400 break-all">{finding.parameter}</div>
                              </div>
                            )}
                          </div>

                          {finding.payload && (
                            <div>
                              <h4 className="font-mono text-[10px] text-red-500 mb-1.5 flex items-center gap-1">
                                <Terminal className="w-3 h-3" /> INJECTED PAYLOAD
                              </h4>
                              <pre className="bg-[#0a0a0a] p-3 text-red-400 font-mono text-[11px] border border-red-500/20 overflow-x-auto whitespace-pre-wrap break-all">
                                {finding.payload}
                              </pre>
                            </div>
                          )}

                          {finding.evidence && (
                            <div>
                              <h4 className="font-mono text-[10px] text-yellow-500 mb-1.5">EVIDENCE</h4>
                              <pre className="bg-[#0a0a0a] p-3 text-yellow-300 font-mono text-[11px] border border-yellow-500/20 overflow-x-auto whitespace-pre-wrap break-all">
                                {finding.evidence}
                              </pre>
                            </div>
                          )}

                          {(finding.request || finding.response) && (
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                              {finding.request && (
                                <div>
                                  <h4 className="font-mono text-[10px] text-muted-foreground mb-1.5">HTTP REQUEST</h4>
                                  <pre className="bg-[#0a0a0a] p-2 text-foreground/70 font-mono text-[10px] border border-border/30 overflow-x-auto whitespace-pre-wrap break-all max-h-24">
                                    {finding.request}
                                  </pre>
                                </div>
                              )}
                              {finding.response && (
                                <div>
                                  <h4 className="font-mono text-[10px] text-muted-foreground mb-1.5">HTTP RESPONSE</h4>
                                  <pre className="bg-[#0a0a0a] p-2 text-foreground/70 font-mono text-[10px] border border-border/30 overflow-x-auto whitespace-pre-wrap break-all max-h-24">
                                    {finding.response}
                                  </pre>
                                </div>
                              )}
                            </div>
                          )}
                        </div>

                        <div className="space-y-4 border-t lg:border-t-0 lg:border-l border-border/30 pt-4 lg:pt-0 lg:pl-5">
                          {finding.aiAnalysis && (
                            <div className="p-3 border border-primary/30 bg-primary/5 relative">
                              <div className="absolute top-0 right-0 p-1 bg-primary text-black font-mono text-[8px] font-bold">AI</div>
                              <p className="text-[11px] text-primary/90 leading-relaxed mt-1">{finding.aiAnalysis}</p>
                            </div>
                          )}
                          <div>
                            <h4 className="font-mono text-[10px] text-cyan-500 mb-1.5">REMEDIATION</h4>
                            <p className="text-xs text-foreground/80 leading-relaxed">{finding.recommendation}</p>
                          </div>
                          {finding.cweId && (
                            <div className="p-2 border border-border/30 bg-black/20">
                              <h4 className="font-mono text-[10px] text-muted-foreground mb-0.5">REFERENCE</h4>
                              <a
                                href={`https://cwe.mitre.org/data/definitions/${finding.cweId?.replace("CWE-", "")}.html`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="font-mono text-[11px] text-primary hover:underline"
                              >
                                {finding.cweId} ↗
                              </a>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
