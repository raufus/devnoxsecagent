import { Router } from "express";
import { z } from "zod";
import { fetchWithTimeout } from "../lib/scanner";
import { runIntruder } from "../lib/advanced-modules";

const router = Router();

const repeaterSchema = z.object({
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]).default("GET"),
  url: z.string().url(),
  headers: z.record(z.string()).optional().default({}),
  body: z.string().optional().default(""),
  followRedirects: z.boolean().optional().default(false),
  timeout: z.number().min(1000).max(30000).optional().default(10000),
});

router.post("/tools/repeater", async (req, res) => {
  const parse = repeaterSchema.safeParse(req.body);
  if (!parse.success) {
    res.status(400).json({ error: "Invalid request", details: parse.error.errors });
    return;
  }

  const { method, url, headers, body, followRedirects, timeout } = parse.data;

  const safeHeaders: Record<string, string> = {
    "User-Agent": "Devnox-Sec-Agent/2.0",
    ...headers,
  };

  const fetchOptions: RequestInit = {
    method,
    headers: safeHeaders,
    redirect: followRedirects ? "follow" : "manual",
  };

  if (body && !["GET", "HEAD"].includes(method)) {
    fetchOptions.body = body;
  }

  const startTime = Date.now();

  try {
    const response = await fetchWithTimeout(url, fetchOptions, timeout);
    const elapsed = Date.now() - startTime;

    const respHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      respHeaders[key] = value;
    });

    let responseBody = "";
    try {
      responseBody = await response.text();
    } catch {
      responseBody = "[Binary or unreadable response]";
    }

    res.json({
      status: response.status,
      statusText: response.statusText,
      headers: respHeaders,
      body: responseBody.slice(0, 50000),
      elapsed,
      url: response.url,
      redirected: response.redirected,
    });
  } catch (err: any) {
    const elapsed = Date.now() - startTime;
    res.status(502).json({
      error: "Request failed",
      message: err?.message || "Unknown error",
      elapsed,
    });
  }
});

// ─── Intruder Tool — 4 Attack Types ─────────────────────────────────────────
const intruderSchema = z.object({
  url: z.string().url(),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("POST"),
  headers: z.record(z.string()).optional().default({}),
  bodyTemplate: z.string().default(""),
  attackType: z.enum(["sniper", "battering_ram", "pitchfork", "cluster_bomb"]).default("sniper"),
  insertionPoints: z.array(z.string()).default(["payload"]),
  payloadSets: z.array(z.array(z.string())).default([[]]),
});

router.post("/tools/intruder", async (req, res) => {
  const parse = intruderSchema.safeParse(req.body);
  if (!parse.success) {
    res.status(400).json({ error: "Invalid request", details: parse.error.errors });
    return;
  }
  const { url, method, headers, bodyTemplate, attackType, insertionPoints, payloadSets } = parse.data;

  // Build request combinations based on attack type
  const combinations: Array<{ payloads: string[]; points: string[] }> = [];
  const set0 = payloadSets[0] || [];
  const set1 = payloadSets[1] || [];

  if (attackType === "sniper") {
    // One insertion point at a time, all payloads
    for (const point of insertionPoints) {
      for (const payload of set0.slice(0, 200)) {
        combinations.push({ payloads: [payload], points: [point] });
      }
    }
  } else if (attackType === "battering_ram") {
    // Same payload in ALL insertion points simultaneously
    for (const payload of set0.slice(0, 200)) {
      combinations.push({ payloads: insertionPoints.map(() => payload), points: insertionPoints });
    }
  } else if (attackType === "pitchfork") {
    // Parallel: set0[i] → point0, set1[i] → point1
    const len = Math.min(set0.length, set1.length || set0.length, 200);
    for (let i = 0; i < len; i++) {
      combinations.push({ payloads: [set0[i], set1[i] || set0[i]], points: insertionPoints.slice(0, 2) });
    }
  } else if (attackType === "cluster_bomb") {
    // Cartesian product of all sets
    const s0 = set0.slice(0, 30);
    const s1 = (set1.length > 0 ? set1 : set0).slice(0, 30);
    for (const p0 of s0) {
      for (const p1 of s1) {
        combinations.push({ payloads: [p0, p1], points: insertionPoints.slice(0, 2) });
      }
    }
  }

  const results = [];
  for (const combo of combinations.slice(0, 500)) {
    let body = bodyTemplate;
    combo.points.forEach((point, i) => {
      body = body.replace(new RegExp(`§${point}§`, "g"), combo.payloads[i] || combo.payloads[0] || "");
    });
    const start = Date.now();
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 10000);
      const response = await fetch(url, {
        method,
        headers: { ...headers, "User-Agent": "DevNox-Intruder/2.0" },
        body: ["GET", "HEAD"].includes(method) ? undefined : body,
        signal: ctrl.signal,
      }).finally(() => clearTimeout(t));
      const responseBody = await response.text();
      const elapsed = Date.now() - start;
      const rb = responseBody.toLowerCase();
      const interesting =
        rb.includes("sql") || rb.includes("mysql") || rb.includes("ora-") ||
        rb.includes("exception") || rb.includes("stack trace") ||
        rb.includes("syntax error") || responseBody.includes(combo.payloads[0]) ||
        elapsed > 4000 || response.status === 500 || response.status === 200;

      results.push({
        payloads: combo.payloads,
        points: combo.points,
        statusCode: response.status,
        responseLength: responseBody.length,
        responseTime: elapsed,
        interesting,
        evidence: interesting ? responseBody.substring(0, 300) : undefined,
      });
    } catch {
      results.push({ payloads: combo.payloads, points: combo.points, statusCode: 0, responseLength: 0, responseTime: Date.now() - start, interesting: false });
    }
  }

  res.json({ results, total: results.length, interesting: results.filter(r => r.interesting).length, attackType });
});

// ─── Fetch Real Payloads from PayloadsAllTheThings / SecLists ─────────────────
router.get("/tools/payloads/:vulnType", async (req, res) => {
  try {
    const { fetchPayloads, VULN_TYPES } = await import("../lib/payload-engine");
    const { vulnType } = req.params;
    const limit = Number(req.query.limit) || 50;
    const payloads = await fetchPayloads(vulnType, limit);
    res.json({ vulnType, payloads, total: payloads.length, source: "PayloadsAllTheThings + SecLists" });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to fetch payloads", message: err?.message });
  }
});

// ─── CVE → Payload Mapping ────────────────────────────────────────────────────
router.get("/tools/payloads/cve/:cveId", async (req, res) => {
  try {
    const { getPayloadsForCVE } = await import("../lib/payload-engine");
    const result = await getPayloadsForCVE(req.params.cveId);
    res.json({ ...result, source: "CVE → PayloadsAllTheThings" });
  } catch (err: any) {
    res.status(500).json({ error: "Failed", message: err?.message });
  }
});

// ─── Shodan Lookup Tool ───────────────────────────────────────────────────────
router.get("/tools/shodan/:ip", async (req, res) => {
  const { queryShodan } = await import("../lib/advanced-modules");
  const result = await queryShodan(req.params.ip);
  if (!result) return res.status(404).json({ error: "Shodan lookup failed or API key not set" });
  res.json(result);
});

// ─── Exploit-DB Search Tool ───────────────────────────────────────────────────
router.get("/tools/exploitdb", async (req, res) => {
  const { q, cve } = req.query as { q?: string; cve?: string };
  if (!q && !cve) {
    return res.status(400).json({ error: "Provide q (search query) or cve parameter" });
  }
  try {
    const { searchExploitDB, searchNVD, searchCIRCL } = await import("../lib/exploit-db");
    const results = await Promise.allSettled([
      q ? searchExploitDB(q) : Promise.resolve([]),
      q ? searchNVD(q, cve) : cve ? searchNVD("", cve) : Promise.resolve([]),
      cve ? searchCIRCL(cve) : Promise.resolve(null),
    ]);
    const exploitDb = results[0].status === "fulfilled" ? results[0].value : [];
    const nvd = results[1].status === "fulfilled" ? results[1].value : [];
    const circl = results[2].status === "fulfilled" && results[2].value ? [results[2].value] : [];
    const all = [...exploitDb, ...nvd, ...circl];
    res.json({ results: all, total: all.length });
  } catch (err: any) {
    res.status(500).json({ error: "Search failed", message: err?.message });
  }
});

export default router;