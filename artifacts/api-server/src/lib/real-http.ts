/**
 * Real HTTP Request Engine
 * Makes actual HTTP calls to target endpoints for real vulnerability testing.
 * No simulation — every result is based on live server responses.
 */

const REQUEST_TIMEOUT = 15000; // 15 seconds
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";

export interface HttpResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  responseTime: number;
  error?: string;
  redirected?: boolean;
  finalUrl?: string;
}

export interface HttpOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string | null;
  timeout?: number;
  followRedirects?: boolean;
}

export async function httpRequest(url: string, opts: HttpOptions = {}): Promise<HttpResult> {
  const start = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeout || REQUEST_TIMEOUT);

  try {
    const response = await fetch(url, {
      method: opts.method || "GET",
      headers: {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        ...opts.headers,
      },
      body: opts.body ?? undefined,
      signal: controller.signal,
      redirect: opts.followRedirects === false ? "manual" : "follow",
    } as RequestInit);

    const rawBody = await response.text();
    const headers: Record<string, string> = {};
    response.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

    return {
      status: response.status,
      headers,
      body: rawBody.slice(0, 8000), // limit to 8KB
      responseTime: Date.now() - start,
      redirected: response.redirected,
      finalUrl: response.url,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      status: 0,
      headers: {},
      body: "",
      responseTime: Date.now() - start,
      error: msg.includes("aborted") ? "Request timed out" : msg,
    };
  } finally {
    clearTimeout(timer);
  }
}

// Build URL with parameter injection
export function buildUrl(endpoint: string, param: string | null, payload: string): string {
  try {
    const u = new URL(endpoint);
    if (param) {
      u.searchParams.set(param, payload);
    } else {
      // Try to inject into first existing param
      const first = [...u.searchParams.keys()][0];
      if (first) u.searchParams.set(first, payload);
    }
    return u.toString();
  } catch {
    // If URL parsing fails, append as query
    const sep = endpoint.includes("?") ? "&" : "?";
    return `${endpoint}${sep}${param || "q"}=${encodeURIComponent(payload)}`;
  }
}

// Build POST body with injection
export function buildPostBody(endpoint: string, param: string | null, payload: string, existingBody?: string | null): string {
  if (existingBody) {
    try {
      const parsed = new URLSearchParams(existingBody);
      if (param && parsed.has(param)) {
        parsed.set(param, payload);
        return parsed.toString();
      }
      if (param) { parsed.set(param, payload); return parsed.toString(); }
    } catch {}
  }
  return `${param || "input"}=${encodeURIComponent(payload)}`;
}

// Detect WAF from response
export function detectWAF(res: HttpResult): { vendor: string; blocked: boolean; confidence: number } {
  const headers = res.headers;
  const body = res.body.toLowerCase();
  const status = res.status;

  if (headers["cf-ray"] || headers["server"]?.includes("cloudflare")) {
    const blocked = status === 403 || body.includes("cloudflare") && (status === 403 || body.includes("ray id"));
    return { vendor: "Cloudflare", blocked, confidence: 97 };
  }
  if (headers["x-amz-cf-id"] || headers["x-amz-request-id"]) {
    return { vendor: "AWS WAF/CloudFront", blocked: status === 403, confidence: 90 };
  }
  if (headers["x-iinfo"] || headers["x-cdn"]?.includes("Incapsula")) {
    return { vendor: "Imperva Incapsula", blocked: status === 403, confidence: 85 };
  }
  if (headers["x-sucuri-id"] || body.includes("sucuri website firewall")) {
    return { vendor: "Sucuri", blocked: true, confidence: 90 };
  }
  if (body.includes("mod_security") || body.includes("modsecurity")) {
    return { vendor: "ModSecurity", blocked: status === 406 || status === 403, confidence: 80 };
  }
  if (headers["x-fw-hash"] || body.includes("fortiweb")) {
    return { vendor: "FortiWeb", blocked: status === 403, confidence: 75 };
  }
  if (status === 403 && (body.includes("blocked") || body.includes("forbidden") || body.includes("access denied"))) {
    return { vendor: "Unknown WAF", blocked: true, confidence: 55 };
  }
  return { vendor: "None", blocked: false, confidence: 5 };
}

// SQL error detection
export function detectSQLError(body: string): boolean {
  const patterns = [
    "you have an error in your sql syntax",
    "mysql_fetch", "mysql_num_rows", "mysql_query",
    "ora-0", "oracle error", "oracle database",
    "sqlstate", "odbc driver",
    "microsoft ole db provider for sql server",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query", "pg_exec", "psql error",
    "syntax error near",
    "unterminated string literal",
    "warning: mysql_",
    "supplied argument is not a valid mysql",
    "[microsoft][odbc sql server driver]",
    "nvarchar", "varchar", "sqlexception",
    "com.mysql.jdbc", "org.postgresql",
  ];
  const bl = body.toLowerCase();
  return patterns.some(p => bl.includes(p));
}

// LFI success detection
export function detectLFISuccess(body: string): boolean {
  const patterns = [
    "root:x:0:0", "root:!:0:", // /etc/passwd
    "[fonts]", "[extensions]", // windows files
    "daemon:x:", "nobody:x:",
    "bin/bash", "bin/sh",
    "# /etc/hosts",
    "[boot loader]", "multi(0)disk(0)",
  ];
  const bl = body.toLowerCase();
  return patterns.some(p => bl.includes(p));
}

// XSS reflection detection
export function detectXSSReflection(body: string, payload: string): boolean {
  // Check if payload appears unencoded
  const rawPayload = payload.toLowerCase();
  const bl = body.toLowerCase();
  if (bl.includes(rawPayload)) return true;
  // Check for partial reflection of key XSS indicators
  if (bl.includes("<script>") || bl.includes("onerror=") || bl.includes("onload=") || bl.includes("javascript:")) return true;
  return false;
}

// CMDi success detection
export function detectCMDISuccess(body: string): boolean {
  const patterns = [
    "uid=", "gid=", "groups=", // Linux id output
    "root@", "www-data", "apache", "nginx",
    "linux ", "darwin ", "windows nt", // uname output
    "/bin/bash", "/usr/bin/",
    "volume serial number",
  ];
  const bl = body.toLowerCase();
  return patterns.some(p => bl.includes(p));
}

// SSRF success detection
export function detectSSRFSuccess(body: string, status: number): boolean {
  const patterns = [
    "ami-id", "instance-id", "iam", "security-credentials", // AWS metadata
    "computemetadata", "serviceaccounts", // GCP
    "metadata/instance", "azure", // Azure
    "internal", "localhost", "127.0.0.",
    "ssh-rsa", "private key", "begin rsa",
    "db_host", "db_password", "database_url",
  ];
  const bl = body.toLowerCase();
  if (patterns.some(p => bl.includes(p))) return true;
  // Different response from baseline (content from internal server)
  if (status === 200 && body.length > 100) return true;
  return false;
}

// CORS misconfiguration detection
export function detectCORSMisconfig(headers: Record<string, string>): { vulnerable: boolean; details: string } {
  const acao = headers["access-control-allow-origin"];
  const acac = headers["access-control-allow-credentials"];
  if (!acao) return { vulnerable: false, details: "No CORS headers present" };
  if (acao === "*" && acac === "true") return { vulnerable: true, details: "ACAO: * with credentials — critical misconfiguration" };
  if (acao === "*") return { vulnerable: true, details: "ACAO: * — any origin can read public data" };
  // Check if attacker origin was reflected
  if (!acao.includes("origin not set") && acac === "true") {
    return { vulnerable: true, details: `ACAO: ${acao} + credentials: true — cross-origin session theft possible` };
  }
  return { vulnerable: false, details: `ACAO: ${acao}` };
}

// Rate limit detection from rapid requests
export function detectRateLimit(responses: HttpResult[]): { limited: boolean; mechanism: string } {
  const statuses = responses.map(r => r.status);
  if (statuses.some(s => s === 429)) return { limited: true, mechanism: "HTTP 429 Too Many Requests" };
  if (statuses.some(s => s === 503)) return { limited: true, mechanism: "HTTP 503 — possible throttling" };
  const hasRetryAfter = responses.some(r => r.headers["retry-after"]);
  if (hasRetryAfter) return { limited: true, mechanism: "Retry-After header detected" };
  const hasCaptcha = responses.some(r => r.body.toLowerCase().includes("captcha") || r.body.toLowerCase().includes("recaptcha"));
  if (hasCaptcha) return { limited: true, mechanism: "CAPTCHA challenge triggered" };
  return { limited: false, mechanism: "No rate limiting detected" };
}

// Tech stack detection from HTTP response
export function detectTechStack(res: HttpResult): string[] {
  const techs: string[] = [];
  const headers = res.headers;
  const body = res.body.toLowerCase();

  // Server header
  if (headers["server"]) {
    const s = headers["server"].toLowerCase();
    if (s.includes("nginx")) techs.push("Nginx");
    if (s.includes("apache")) techs.push("Apache");
    if (s.includes("iis")) techs.push("IIS");
    if (s.includes("cloudflare")) techs.push("Cloudflare");
    if (s.includes("openresty")) techs.push("OpenResty");
    if (s.includes("lighttpd")) techs.push("Lighttpd");
  }

  // X-Powered-By
  if (headers["x-powered-by"]) {
    const xpb = headers["x-powered-by"];
    techs.push(xpb.split(",")[0].trim());
  }

  // CDN / WAF
  if (headers["cf-ray"]) techs.push("Cloudflare");
  if (headers["x-amz-cf-id"]) techs.push("AWS CloudFront");
  if (headers["x-iinfo"]) techs.push("Imperva Incapsula");

  // Framework detection from headers/body
  if (headers["x-aspnet-version"] || headers["x-aspnetmvc-version"]) techs.push("ASP.NET");
  if (headers["x-django-version"] || body.includes("csrfmiddlewaretoken")) techs.push("Django");
  if (body.includes("laravel") || headers["set-cookie"]?.includes("laravel_session")) techs.push("Laravel");
  if (body.includes("yii") || body.includes("yiiframework")) techs.push("Yii");
  if (body.includes("wp-content") || body.includes("wp-json")) techs.push("WordPress");
  if (body.includes("joomla") || body.includes("/components/com_")) techs.push("Joomla");
  if (body.includes("drupal") || body.includes("/sites/default/")) techs.push("Drupal");
  if (body.includes("symfony") || headers["x-symfony-cache"]) techs.push("Symfony");

  // Language detection
  if (headers["x-php-version"] || headers["x-powered-by"]?.toLowerCase().includes("php")) techs.push("PHP");
  if (headers["set-cookie"]?.includes("PHPSESSID")) techs.push("PHP");
  if (headers["set-cookie"]?.includes("JSESSIONID")) techs.push("Java");
  if (headers["x-powered-by"]?.includes("Express")) techs.push("Node.js/Express");

  return [...new Set(techs)];
}

// Test directory existence
export async function probeUrl(baseUrl: string, path: string): Promise<{ path: string; status: number; size: number; interesting: boolean; headers: Record<string, string> }> {
  try {
    const base = baseUrl.replace(/\/$/, "");
    const url = `${base}${path}`;
    const res = await httpRequest(url, { timeout: 8000 });
    const interesting = res.status === 200 || res.status === 301 || res.status === 302 || res.status === 401 || res.status === 403;
    return { path, status: res.status, size: res.body.length, interesting, headers: res.headers };
  } catch {
    return { path, status: 0, size: 0, interesting: false, headers: {} };
  }
}

// Probe multiple paths concurrently
export async function probePaths(baseUrl: string, paths: string[], concurrency = 8): Promise<{ path: string; status: number; size: number; interesting: boolean }[]> {
  const results = [];
  for (let i = 0; i < paths.length; i += concurrency) {
    const batch = paths.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(p => probeUrl(baseUrl, p)));
    results.push(...batchResults);
  }
  return results;
}

// Sleep utility for timing tests
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
