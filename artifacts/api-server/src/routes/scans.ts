import { Router, type IRouter, Request, Response } from "express";
import { db } from "@workspace/db";
import { scansTable, findingsTable, scanEventsTable, reconDataTable, graphNodesTable, graphEdgesTable, aiDecisionsTable } from "@workspace/db/schema";
import { eq, and, desc, count } from "drizzle-orm";
import { randomUUID } from "crypto";
import { runScan, scanEmitter } from "../lib/scanner";
import { runValidationEngine, runExploitEngine, runBypassEngine } from "../lib/validation-engines.js";
import { runAIDecisionEngine, runChainEngine, runTargetProfiler } from "../lib/advanced-engines-analysis.js";
import { runAPITestingEngine } from "../lib/api-testing-engine.js";

const router: IRouter = Router();

// Helper to safely extract scanId from params
const getScanId = (params: any): string => params.scanId as string;

router.get("/scans", async (req: Request, res: Response) => {
  try {
    const limit = Number(req.query.limit) || 20;
    const offset = Number(req.query.offset) || 0;
    const scans = await db.select().from(scansTable).orderBy(desc(scansTable.createdAt)).limit(limit).offset(offset);
    const [totalResult] = await db.select({ total: count() }).from(scansTable);
    res.json({ scans, total: totalResult?.total ?? 0 });
  } catch (err) {
    req.log.error({ err }, "Failed to list scans");
    res.status(500).json({ error: "internal_error", message: "Failed to list scans" });
  }
});

router.post("/scans", async (req: Request, res: Response) => {
  try {
    const { targetUrl, scanType, modules, consentAcknowledged } = req.body;

    if (!targetUrl || !scanType || !consentAcknowledged) {
      return res.status(400).json({ error: "validation_error", message: "targetUrl, scanType, and consentAcknowledged are required" });
    }
    if (!["quick", "full", "deep"].includes(scanType)) {
      return res.status(400).json({ error: "validation_error", message: "Invalid scanType" });
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(targetUrl);
      if (!["http:", "https:"].includes(parsedUrl.protocol)) {
        return res.status(400).json({ error: "validation_error", message: "URL must use http or https protocol" });
      }
    } catch {
      return res.status(400).json({ error: "validation_error", message: "Invalid URL format" });
    }

    const defaultModules = ["recon", "headers", "xss", "sqli", "ssrf", "csrf"];
    const enabledModules = modules?.length ? modules : defaultModules;
    const scanId = randomUUID();

    await db.insert(scansTable).values({
      id: scanId,
      targetUrl,
      scanType,
      modules: enabledModules,
      status: "pending",
      progress: 0,
      currentPhase: "idle",
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      techStack: [],
      subdomains: [],
      endpoints: [],
    });

    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    setImmediate(() => runScan(scanId));
    res.status(201).json(scan);
  } catch (err) {
    req.log.error({ err }, "Failed to create scan");
    res.status(500).json({ error: "internal_error", message: "Failed to create scan" });
  }
});

router.get("/scans/:scanId", async (req: Request, res: Response) => {
  try {
    const scanId = req.params.scanId as string;
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });
    res.json(scan);
  } catch (err) {
    req.log.error({ err }, "Failed to get scan");
    res.status(500).json({ error: "internal_error", message: "Failed to get scan" });
  }
});

router.delete("/scans/:scanId", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });
    await db.delete(findingsTable).where(eq(findingsTable.scanId, scanId));
    await db.delete(scanEventsTable).where(eq(scanEventsTable.scanId, scanId));
    await db.delete(scansTable).where(eq(scansTable.id, scanId));
    res.json({ success: true, message: "Scan deleted" });
  } catch (err) {
    req.log.error({ err }, "Failed to delete scan");
    res.status(500).json({ error: "internal_error", message: "Failed to delete scan" });
  }
});

router.post("/scans/:scanId/cancel", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });

    await db.update(scansTable)
      .set({ status: "cancelled", completedAt: new Date() })
      .where(eq(scansTable.id, scanId));

    const [updated] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    scanEmitter.emit(`scan:${scanId}`, { type: "cancelled", data: { status: "cancelled" } });
    res.json(updated);
  } catch (err) {
    req.log.error({ err }, "Failed to cancel scan");
    res.status(500).json({ error: "internal_error", message: "Failed to cancel scan" });
  }
});

router.get("/scans/:scanId/findings", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const { severity, type } = req.query;
    const conditions = [eq(findingsTable.scanId, scanId)];
    if (severity) conditions.push(eq(findingsTable.severity, severity as "critical" | "high" | "medium" | "low" | "info"));
    if (type) conditions.push(eq(findingsTable.type, type as string));
    const findings = await db.select().from(findingsTable).where(and(...conditions)).orderBy(desc(findingsTable.createdAt));
    res.json({ findings, total: findings.length });
  } catch (err) {
    req.log.error({ err }, "Failed to get findings");
    res.status(500).json({ error: "internal_error", message: "Failed to get findings" });
  }
});

router.get("/scans/:scanId/events", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const events = await db.select().from(scanEventsTable).where(eq(scanEventsTable.scanId, scanId)).orderBy(scanEventsTable.createdAt);
    res.json({ events });
  } catch (err) {
    req.log.error({ err }, "Failed to get events");
    res.status(500).json({ error: "internal_error", message: "Failed to get events" });
  }
});

router.get("/scans/:scanId/events-stream", async (req: Request, res: Response) => {
  const scanId = getScanId(req.params);
  const scan = await db.select({ id: scansTable.id }).from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
  if (!scan[0]) return res.status(404).json({ error: "not_found", message: "Scan not found" });

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const sendEvent = (data: object) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  const existingEvents = await db.select().from(scanEventsTable).where(eq(scanEventsTable.scanId, scanId)).orderBy(scanEventsTable.createdAt);
  for (const event of existingEvents) sendEvent({ type: "event", data: event });

  const listener = (payload: object) => sendEvent(payload);
  scanEmitter.on(`scan:${scanId}`, listener);
  const keepAlive = setInterval(() => res.write(":keepalive\n\n"), 15000);

  req.on("close", () => {
    clearInterval(keepAlive);
    scanEmitter.off(`scan:${scanId}`, listener);
  });
});

router.get("/scans/:scanId/report", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });

    const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, scanId)).orderBy(desc(findingsTable.createdAt));
    const criticalCount = findings.filter(f => f.severity === "critical").length;
    const highCount = findings.filter(f => f.severity === "high").length;
    const mediumCount = findings.filter(f => f.severity === "medium").length;

    let riskScore = 0;
    for (const f of findings) {
      if (f.severity === "critical") riskScore += 40;
      else if (f.severity === "high") riskScore += 25;
      else if (f.severity === "medium") riskScore += 10;
      else if (f.severity === "low") riskScore += 5;
      else riskScore += 1;
    }
    riskScore = Math.min(100, riskScore);

    let riskLevel = "Low";
    if (criticalCount > 0) riskLevel = "Critical";
    else if (highCount > 0) riskLevel = "High";
    else if (mediumCount > 0) riskLevel = "Medium";

    const types = [...new Set(findings.map(f => f.type))];
    const summary = `Security assessment of ${scan.targetUrl} completed with ${findings.length} finding(s). Risk Level: ${riskLevel}. ` +
      (findings.length > 0
        ? `Vulnerability types detected: ${types.join(", ")}. Immediate attention required for ${criticalCount + highCount} critical/high severity issues.`
        : "No significant vulnerabilities detected. Maintain regular security assessments.");

    res.json({ scan, findings, summary, riskScore, generatedAt: new Date().toISOString() });
  } catch (err) {
    req.log.error({ err }, "Failed to get report");
    res.status(500).json({ error: "internal_error", message: "Failed to get report" });
  }
});

router.get("/scans/:scanId/exploit", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const allDecisions = await db.select().from(aiDecisionsTable).where(eq(aiDecisionsTable.scanId, scanId));
    const exploitationDecision = allDecisions.find(d => d.phase === "exploitation");
    if (!exploitationDecision) return res.json({ exploitReport: null, message: "Exploit data not yet available" });

    let exploitReport = null;
    try { exploitReport = JSON.parse(exploitationDecision.input || "null"); } catch { exploitReport = null; }

    res.json({
      exploitReport,
      decision: exploitationDecision.decision,
      reasoning: exploitationDecision.reasoning,
      actions: exploitationDecision.actions,
      confidence: exploitationDecision.confidence,
      createdAt: exploitationDecision.createdAt,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to get exploit data");
    res.status(500).json({ error: "internal_error", message: "Failed to get exploit data" });
  }
});

router.get("/scans/:scanId/recon", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [recon] = await db.select().from(reconDataTable).where(eq(reconDataTable.scanId, scanId)).limit(1);
    if (!recon) return res.json({ reconData: null, message: "Recon data not yet available or not started" });
    res.json({ reconData: recon });
  } catch (err) {
    req.log.error({ err }, "Failed to get recon data");
    res.status(500).json({ error: "internal_error", message: "Failed to get recon data" });
  }
});

router.get("/scans/:scanId/graph", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const nodes = await db.select().from(graphNodesTable).where(eq(graphNodesTable.scanId, scanId));
    const edges = await db.select().from(graphEdgesTable).where(eq(graphEdgesTable.scanId, scanId));
    res.json({ nodes, edges });
  } catch (err) {
    req.log.error({ err }, "Failed to get attack graph");
    res.status(500).json({ error: "internal_error", message: "Failed to get attack graph" });
  }
});

router.get("/scans/:scanId/ai-decisions", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const decisions = await db.select().from(aiDecisionsTable).where(eq(aiDecisionsTable.scanId, scanId)).orderBy(aiDecisionsTable.createdAt);
    res.json({ decisions });
  } catch (err) {
    req.log.error({ err }, "Failed to get AI decisions");
    res.status(500).json({ error: "internal_error", message: "Failed to get AI decisions" });
  }
});

// ─── ADVANCED ANALYSIS ROUTES ────────────────────────────────────────────────

router.post("/scans/:scanId/advanced/validate", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });

    const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, scanId));
    const results = [];
    let totalValidated = 0;
    let falsePositivesFound = 0;
    let confirmedVulnerabilities = 0;
    let totalScore = 0;

    for (const finding of findings.slice(0, 20)) {
      const validationResult = await runValidationEngine({
        id: finding.id,
        type: finding.type,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        endpoint: finding.endpoint,
        method: finding.method || "GET",
        parameter: finding.parameter || "",
        payload: finding.payload || "",
        evidence: finding.evidence || "",
        request: finding.request || "",
        response: finding.response || "",
        cweId: finding.cweId || "",
        cvssScore: finding.cvssScore || 0,
        falsePositive: finding.falsePositive || false,
      });

      totalValidated++;
      totalScore += validationResult.validationScore;
      if (validationResult.isFalsePositive) {
        falsePositivesFound++;
        await db.update(findingsTable).set({ falsePositive: true }).where(eq(findingsTable.id, finding.id));
      } else {
        confirmedVulnerabilities++;
      }

      results.push({
        id: finding.id,
        findingTitle: finding.title,
        severity: finding.severity,
        ...validationResult,
      });
    }

    const avgValidationScore = totalValidated > 0 ? Math.round(totalScore / totalValidated) : 0;

    res.json({
      totalValidated,
      falsePositivesFound,
      confirmedVulnerabilities,
      avgValidationScore,
      results,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to run validation engine");
    res.status(500).json({ error: "internal_error", message: "Failed to run validation engine" });
  }
});

router.post("/scans/:scanId/advanced/exploit", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });

    const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, scanId));
    const results = [];
    let totalExploited = 0;
    let exploitsSucceeded = 0;
    let exploitsFailed = 0;

    for (const finding of findings.filter(f => !f.falsePositive).slice(0, 15)) {
      const validation = { isFalsePositive: false, validationScore: 75 } as any;
      const exploitResult = await runExploitEngine({
        id: finding.id,
        type: finding.type,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        endpoint: finding.endpoint,
        method: finding.method || "GET",
        parameter: finding.parameter || "",
        payload: finding.payload || "",
        evidence: finding.evidence || "",
        request: finding.request || "",
        response: finding.response || "",
        cweId: finding.cweId || "",
        cvssScore: finding.cvssScore || 0,
        falsePositive: finding.falsePositive || false,
      }, validation);

      totalExploited++;
      if (exploitResult.exploitSuccess) exploitsSucceeded++;
      else exploitsFailed++;

      results.push({
        id: finding.id,
        findingTitle: finding.title,
        severity: finding.severity,
        ...exploitResult,
      });
    }

    const successRate = totalExploited > 0 ? Math.round((exploitsSucceeded / totalExploited) * 100) : 0;

    res.json({
      totalExploited,
      exploitsSucceeded,
      exploitsFailed,
      successRate,
      results,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to run exploit engine");
    res.status(500).json({ error: "internal_error", message: "Failed to run exploit engine" });
  }
});

router.post("/scans/:scanId/advanced/bypass", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });

    const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, scanId));
    const results = [];
    let bypassesSucceeded = 0;
    const allBypassTechniques: string[] = [];
    
    // Parse techStack - handle both array and JSON string
    let techStack: string[] = [];
    try {
      if (Array.isArray(scan.techStack)) {
        techStack = scan.techStack;
      } else if (typeof scan.techStack === 'string') {
        techStack = JSON.parse(scan.techStack);
      } else if (scan.techStack) {
        techStack = [String(scan.techStack)];
      }
    } catch (e) {
      techStack = [];
    }
    
    const wafDetected = techStack.some((t: string) => t.toLowerCase().includes("cloudflare") || t.toLowerCase().includes("waf")) || false;
    const cloudflareDetected = techStack.some((t: string) => t.toLowerCase().includes("cloudflare")) || false;

    for (const finding of findings.filter(f => !f.falsePositive).slice(0, 15)) {
      const bypassResult = await runBypassEngine({
        id: finding.id,
        type: finding.type,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        endpoint: finding.endpoint,
        method: finding.method || "GET",
        parameter: finding.parameter || "",
        payload: finding.payload || "",
        evidence: finding.evidence || "",
        request: finding.request || "",
        response: finding.response || "",
        cweId: finding.cweId || "",
        cvssScore: finding.cvssScore || 0,
        falsePositive: finding.falsePositive || false,
      });

      if (bypassResult.bypassSuccess) {
        bypassesSucceeded++;
        try {
          await db.update(findingsTable).set({ bypassConfirmed: true }).where(eq(findingsTable.id, finding.id));
        } catch (err) {
          console.warn('Could not update bypassConfirmed field:', err);
        }
      }

      bypassResult.bypassTechniquesUsed.forEach((t: string) => {
        if (!allBypassTechniques.includes(t)) allBypassTechniques.push(t);
      });

      results.push({
        id: finding.id,
        findingTitle: finding.title,
        severity: finding.severity,
        ...bypassResult,
      });
    }

    res.json({
      wafDetected,
      cloudflareDetected,
      bypassesSucceeded,
      allBypassTechniques,
      results,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to run bypass engine");
    res.status(500).json({ error: "internal_error", message: "Failed to run bypass engine" });
  }
});

router.get("/scans/:scanId/advanced/ai-attack-plan", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });

    const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, scanId));
    const findingsInput = findings.map(f => ({
      id: f.id,
      type: f.type,
      title: f.title,
      description: f.description,
      severity: f.severity,
      endpoint: f.endpoint,
      method: f.method || "GET",
      parameter: f.parameter || "",
      payload: f.payload || "",
      evidence: f.evidence || "",
      request: f.request || "",
      response: f.response || "",
      cweId: f.cweId || "",
      cvssScore: f.cvssScore || 0,
      falsePositive: f.falsePositive || false,
    }));

    // Parse techStack - handle both array and JSON string
    let techStack: string[] = [];
    try {
      if (Array.isArray(scan.techStack)) {
        techStack = scan.techStack;
      } else if (typeof scan.techStack === 'string') {
        techStack = JSON.parse(scan.techStack);
      } else if (scan.techStack) {
        techStack = [String(scan.techStack)];
      }
    } catch (e) {
      techStack = [];
    }
    
    const aiDecision = runAIDecisionEngine(findingsInput, techStack);
    res.json(aiDecision);
  } catch (err) {
    req.log.error({ err }, "Failed to run AI decision engine");
    res.status(500).json({ error: "internal_error", message: "Failed to run AI decision engine" });
  }
});

router.get("/scans/:scanId/advanced/chains", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });

    const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, scanId));
    const findingsInput = findings.map(f => ({
      id: f.id,
      type: f.type,
      title: f.title,
      description: f.description,
      severity: f.severity,
      endpoint: f.endpoint,
      method: f.method,
      parameter: f.parameter,
      payload: f.payload,
      evidence: f.evidence,
      request: f.request,
      response: f.response,
      cweId: f.cweId,
      cvssScore: f.cvssScore,
      falsePositive: f.falsePositive || false,
    }));

    const chains = runChainEngine(findingsInput);
    res.json({ chains });
  } catch (err) {
    req.log.error({ err }, "Failed to run chain engine");
    res.status(500).json({ error: "internal_error", message: "Failed to run chain engine" });
  }
});

router.get("/scans/:scanId/advanced/profile", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });

    const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, scanId));
    const findingsInput = findings.map(f => ({
      id: f.id,
      type: f.type,
      title: f.title,
      description: f.description,
      severity: f.severity,
      endpoint: f.endpoint,
      method: f.method || "GET",
      parameter: f.parameter || "",
      payload: f.payload || "",
      evidence: f.evidence || "",
      request: f.request || "",
      response: f.response || "",
      cweId: f.cweId || "",
      cvssScore: f.cvssScore || 0,
      falsePositive: f.falsePositive || false,
    }));

    // Parse all arrays - handle both array and JSON string formats
    let techStack: string[] = [];
    let endpoints: string[] = [];
    let subdomains: string[] = [];
    
    try {
      if (Array.isArray(scan.techStack)) {
        techStack = scan.techStack;
      } else if (typeof scan.techStack === 'string') {
        techStack = JSON.parse(scan.techStack);
      } else if (scan.techStack) {
        techStack = [String(scan.techStack)];
      }
    } catch (e) {
      techStack = [];
    }
    
    try {
      if (Array.isArray(scan.endpoints)) {
        endpoints = scan.endpoints;
      } else if (typeof scan.endpoints === 'string') {
        endpoints = JSON.parse(scan.endpoints);
      } else if (scan.endpoints) {
        endpoints = [String(scan.endpoints)];
      }
    } catch (e) {
      endpoints = [];
    }
    
    try {
      if (Array.isArray(scan.subdomains)) {
        subdomains = scan.subdomains;
      } else if (typeof scan.subdomains === 'string') {
        subdomains = JSON.parse(scan.subdomains);
      } else if (scan.subdomains) {
        subdomains = [String(scan.subdomains)];
      }
    } catch (e) {
      subdomains = [];
    }

    // runTargetProfiler is now async
    const profile = await runTargetProfiler({
      targetUrl: scan.targetUrl,
      techStack,
      endpoints,
      subdomains,
      findings: findingsInput,
    });

    res.json(profile);
  } catch (err) {
    req.log.error({ err }, "Failed to run target profiler");
    res.status(500).json({ error: "internal_error", message: "Failed to run target profiler" });
  }
});

// ─── API TESTING ROUTES ────────────────────────────────────────────────

router.post("/scans/:scanId/advanced/api-test", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });

    // Parse endpoints array
    let endpoints: string[] = [];
    try {
      if (Array.isArray(scan.endpoints)) {
        endpoints = scan.endpoints;
      } else if (typeof scan.endpoints === 'string') {
        endpoints = JSON.parse(scan.endpoints);
      } else if (scan.endpoints) {
        endpoints = [String(scan.endpoints)];
      }
    } catch (e) {
      endpoints = [];
    }

    // Run automatic API testing
    const testResults = await runAPITestingEngine(scan.targetUrl, endpoints);

    res.json(testResults);
  } catch (err) {
    req.log.error({ err }, "Failed to run API testing engine");
    res.status(500).json({ error: "internal_error", message: "Failed to run API testing engine" });
  }
});

router.post("/scans/:scanId/test-api", async (req: Request, res: Response) => {
  try {
    const scanId = getScanId(req.params);
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan) return res.status(404).json({ error: "not_found", message: "Scan not found" });

    const { url, method = 'GET', headers = {}, body } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: "validation_error", message: "URL is required" });
    }

    // Make the HTTP request
    const fetchOptions: RequestInit = {
      method,
      headers: {
        'User-Agent': 'DevNox-SecAgent/1.0',
        ...headers,
      },
    };

    if (body && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
      fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
      if (!headers['Content-Type']) {
        (fetchOptions.headers as Record<string, string>)['Content-Type'] = 'application/json';
      }
    }

    const response = await fetch(url, fetchOptions);
    const responseBody = await response.text();

    res.json({
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      body: responseBody,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to test API endpoint");
    res.status(500).json({ 
      error: "internal_error", 
      message: err instanceof Error ? err.message : "Failed to test API endpoint",
      status: 0,
      body: '',
    });
  }
});

export default router;
