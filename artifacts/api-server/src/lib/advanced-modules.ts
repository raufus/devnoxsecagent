import { logger } from "./logger";

const UA = "DevNox-SecAgent/2.0 (Security Scanner)";

async function fetchWithTimeout(url: string, opts: RequestInit = {}, ms = 6000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(t); }
}

// ─── Shodan API Integration ───────────────────────────────────────────────────

export interface ShodanResult {
  ip: string;
  ports: number[];
  services: Array<{ port: number; service: string; banner?: string; version?: string }>;
  vulns: string[];
  org: string;
  country: string;
  os?: string;
  hostnames: string[];
  tags: string[];
}

export async function queryShodan(ip: string): Promise<ShodanResult | null> {
  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) {
    logger.warn("SHODAN_API_KEY not set — skipping Shodan lookup");
    return null;
  }
  try {
    const res = await fetchWithTimeout(
      `https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`,
      { headers: { "User-Agent": UA } }, 10000
    );
    if (!res.ok) return null;
    const data = await res.json() as Record<string, unknown>;
    const ports = (data["ports"] as number[]) || [];
    const services: ShodanResult["services"] = [];
    if (Array.isArray(data["data"])) {
      for (const svc of data["data"] as Record<string, unknown>[]) {
        services.push({
          port: svc["port"] as number,
          service: (svc["_shodan"] as Record<string, unknown>)?.["module"] as string || "unknown",
          banner: (svc["data"] as string || "").substring(0, 200),
          version: svc["version"] as string || undefined,
        });
      }
    }
    return {
      ip,
      ports,
      services,
      vulns: Object.keys((data["vulns"] as Record<string, unknown>) || {}),
      org: data["org"] as string || "",
      country: data["country_name"] as string || "",
      os: data["os"] as string || undefined,
      hostnames: (data["hostnames"] as string[]) || [],
      tags: (data["tags"] as string[]) || [],
    };
  } catch (err) {
    logger.warn({ err }, "Shodan query failed");
    return null;
  }
}

// ─── IDOR Detection ───────────────────────────────────────────────────────────

export async function checkIDORAdvanced(
  targetUrl: string,
  crawlUrls: string[],
  addFinding: Function,
  scanId: string
): Promise<void> {
  const base = new URL(targetUrl).origin;
  const idPatterns = [
    /\/(\d+)(\/|$|\?)/,
    /[?&](id|user_id|account|order|invoice|file|doc|record|item|product)=(\d+)/i,
    /\/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/i,
  ];

  const candidates: Array<{ url: string; param: string; value: string }> = [];

  for (const url of [targetUrl, ...crawlUrls].slice(0, 30)) {
    for (const pattern of idPatterns) {
      const m = url.match(pattern);
      if (m) {
        candidates.push({ url, param: "id", value: m[1] || m[2] });
        break;
      }
    }
  }

  // Also check common API patterns
  const apiEndpoints = [
    `${base}/api/users/1`, `${base}/api/users/2`,
    `${base}/api/orders/1`, `${base}/api/profile/1`,
    `${base}/api/account/1`, `${base}/user/1`,
    `${base}/profile/1`, `${base}/account/1`,
  ];

  for (const ep of apiEndpoints) {
    try {
      const r1 = await fetchWithTimeout(ep, { headers: { "User-Agent": UA } }, 4000);
      if (r1.status === 200) {
        const body1 = await r1.text();
        const ep2 = ep.replace(/\/1$/, "/2").replace(/\/1\?/, "/2?");
        const r2 = await fetchWithTimeout(ep2, { headers: { "User-Agent": UA } }, 4000);
        if (r2.status === 200) {
          const body2 = await r2.text();
          if (body1 !== body2 && body2.length > 50) {
            await addFinding(scanId, {
              type: "IDOR",
              title: `IDOR — Unauthenticated Access to Sequential Resource IDs`,
              description: `The endpoint '${ep}' returns different data for IDs 1 and 2 without authentication. This indicates Insecure Direct Object Reference — an attacker can enumerate all resources by incrementing the ID parameter, accessing other users' data.`,
              severity: "high",
              endpoint: ep,
              method: "GET",
              parameter: "id",
              payload: `${ep} → ${ep2}`,
              evidence: `ID=1 returned ${body1.length} bytes, ID=2 returned ${body2.length} bytes — both accessible without auth`,
              recommendation: "Implement object-level authorization checks. Verify the requesting user owns the resource before returning it. Use UUIDs instead of sequential IDs. Add authentication middleware to all resource endpoints.",
              cweId: "CWE-639",
              cvssScore: 8.1,
              aiAnalysis: "IDOR allows attackers to access any user's data by simply changing the ID in the URL. Combined with a user enumeration vulnerability, this can lead to full data breach.",
            });
            return;
          }
        }
      }
    } catch { }
  }

  // Test URL-based IDOR from crawled pages
  for (const { url, value } of candidates.slice(0, 5)) {
    try {
      const nextId = String(parseInt(value) + 1);
      const altUrl = url.replace(value, nextId);
      const [r1, r2] = await Promise.all([
        fetchWithTimeout(url, { headers: { "User-Agent": UA } }, 4000),
        fetchWithTimeout(altUrl, { headers: { "User-Agent": UA } }, 4000),
      ]);
      if (r1.status === 200 && r2.status === 200) {
        const [b1, b2] = await Promise.all([r1.text(), r2.text()]);
        if (b1 !== b2 && b2.length > 100) {
          await addFinding(scanId, {
            type: "IDOR",
            title: `IDOR — Sequential ID Enumeration on '${new URL(url).pathname}'`,
            description: `Accessing '${url}' (ID: ${value}) and '${altUrl}' (ID: ${nextId}) both return different valid responses without authorization checks. An attacker can enumerate all records.`,
            severity: "high",
            endpoint: url,
            method: "GET",
            parameter: "id",
            payload: `Original: ${value} → Modified: ${nextId}`,
            evidence: `Both IDs return HTTP 200 with different content (${b1.length} vs ${b2.length} bytes)`,
            recommendation: "Add server-side authorization: verify session user owns the requested resource. Use non-sequential UUIDs for resource identifiers.",
            cweId: "CWE-639",
            cvssScore: 7.5,
          });
        }
      }
    } catch { }
  }
}

// ─── Auth Bypass Testing ──────────────────────────────────────────────────────

export async function checkAuthBypass(
  targetUrl: string,
  addFinding: Function,
  scanId: string
): Promise<void> {
  const base = new URL(targetUrl).origin;

  // 1. Default credentials test
  const loginEndpoints = [
    `${base}/login`, `${base}/admin/login`, `${base}/wp-login.php`,
    `${base}/administrator`, `${base}/api/login`, `${base}/api/auth/login`,
    `${base}/auth/login`, `${base}/signin`, `${base}/api/signin`,
  ];

  const defaultCreds = [
    { user: "admin", pass: "admin" },
    { user: "admin", pass: "password" },
    { user: "admin", pass: "123456" },
    { user: "admin", pass: "admin123" },
    { user: "root", pass: "root" },
    { user: "test", pass: "test" },
    { user: "guest", pass: "guest" },
    { user: "administrator", pass: "administrator" },
  ];

  for (const ep of loginEndpoints) {
    try {
      const probe = await fetchWithTimeout(ep, { headers: { "User-Agent": UA } }, 4000);
      if (probe.status !== 200 && probe.status !== 405) continue;

      for (const cred of defaultCreds.slice(0, 4)) {
        try {
          const res = await fetchWithTimeout(ep, {
            method: "POST",
            headers: { "Content-Type": "application/json", "User-Agent": UA },
            body: JSON.stringify({ username: cred.user, password: cred.pass }),
          }, 5000);

          const body = await res.text();
          const isSuccess = res.status === 200 &&
            (body.includes("token") || body.includes("dashboard") ||
             body.includes("welcome") || body.includes("success") ||
             res.headers.get("set-cookie")?.includes("session"));

          if (isSuccess) {
            await addFinding(scanId, {
              type: "Auth Bypass",
              title: `Default Credentials Accepted — ${cred.user}:${cred.pass}`,
              description: `The login endpoint '${ep}' accepted default credentials '${cred.user}:${cred.pass}'. This allows unauthorized access to the application with administrative or user-level privileges.`,
              severity: "critical",
              endpoint: ep,
              method: "POST",
              payload: JSON.stringify({ username: cred.user, password: cred.pass }),
              evidence: `HTTP ${res.status} — Response contains authentication success indicators`,
              recommendation: "Immediately change all default credentials. Enforce strong password policies. Implement account lockout after failed attempts. Add MFA for admin accounts.",
              cweId: "CWE-521",
              cvssScore: 9.8,
              aiAnalysis: "Default credentials provide immediate full access. This is one of the most critical vulnerabilities — attackers actively scan for default credentials using automated tools.",
            });
            return;
          }
        } catch { }
      }
    } catch { }
  }

  // 2. JWT None Algorithm Attack
  const jwtEndpoints = [
    `${base}/api/profile`, `${base}/api/me`, `${base}/api/user`,
    `${base}/api/admin`, `${base}/dashboard`,
  ];

  const fakeAdminJwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ.";

  for (const ep of jwtEndpoints) {
    try {
      const res = await fetchWithTimeout(ep, {
        headers: { "Authorization": `Bearer ${fakeAdminJwt}`, "User-Agent": UA },
      }, 4000);
      if (res.status === 200) {
        const body = await res.text();
        if (body.length > 50 && !body.includes("unauthorized") && !body.includes("invalid")) {
          await addFinding(scanId, {
            type: "Auth Bypass",
            title: `JWT None Algorithm Attack — Authentication Bypassed`,
            description: `The endpoint '${ep}' accepted a JWT token with 'alg: none' (no signature). This means the server does not verify JWT signatures, allowing any attacker to forge tokens with arbitrary claims including admin role.`,
            severity: "critical",
            endpoint: ep,
            method: "GET",
            payload: fakeAdminJwt,
            evidence: `HTTP 200 returned with forged JWT (alg:none, role:admin)`,
            recommendation: "Always verify JWT signatures server-side. Reject tokens with 'none' algorithm. Use a strong secret (256+ bits) for HS256 or proper RSA keys for RS256. Use a battle-tested JWT library.",
            cweId: "CWE-347",
            cvssScore: 9.8,
            aiAnalysis: "JWT none algorithm attack allows complete authentication bypass. An attacker can impersonate any user including administrators by crafting unsigned tokens.",
          });
          return;
        }
      }
    } catch { }
  }

  // 3. SQL Injection Auth Bypass
  const sqlBypassPayloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' OR 'x'='x",
  ];

  for (const ep of loginEndpoints.slice(0, 3)) {
    for (const payload of sqlBypassPayloads) {
      try {
        const res = await fetchWithTimeout(ep, {
          method: "POST",
          headers: { "Content-Type": "application/json", "User-Agent": UA },
          body: JSON.stringify({ username: payload, password: payload }),
        }, 5000);
        const body = await res.text();
        if (res.status === 200 && (body.includes("token") || body.includes("dashboard") || body.includes("welcome"))) {
          await addFinding(scanId, {
            type: "Auth Bypass",
            title: `SQL Injection Authentication Bypass`,
            description: `The login endpoint '${ep}' is vulnerable to SQL injection authentication bypass. Using payload '${payload}' in the username field bypasses password verification entirely.`,
            severity: "critical",
            endpoint: ep,
            method: "POST",
            payload,
            evidence: `HTTP 200 with auth success indicators using SQLi payload`,
            recommendation: "Use parameterized queries / prepared statements. Never concatenate user input into SQL queries. Use an ORM. Implement input validation.",
            cweId: "CWE-89",
            cvssScore: 9.8,
          });
          return;
        }
      } catch { }
    }
  }
}

// ─── GraphQL Security Testing ─────────────────────────────────────────────────

export async function checkGraphQL(
  targetUrl: string,
  addFinding: Function,
  scanId: string
): Promise<void> {
  const base = new URL(targetUrl).origin;
  const gqlEndpoints = [
    `${base}/graphql`, `${base}/api/graphql`, `${base}/gql`,
    `${base}/api/gql`, `${base}/query`, `${base}/api/query`,
  ];

  for (const ep of gqlEndpoints) {
    try {
      // 1. Introspection query — reveals full schema
      const introspectionQuery = `{"query":"{__schema{types{name fields{name}}}}"}`;
      const res = await fetchWithTimeout(ep, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": UA },
        body: introspectionQuery,
      }, 6000);

      if (res.status === 200) {
        const body = await res.text();
        if (body.includes("__schema") || body.includes("types")) {
          await addFinding(scanId, {
            type: "GraphQL",
            title: `GraphQL Introspection Enabled — Full Schema Exposed`,
            description: `The GraphQL endpoint '${ep}' has introspection enabled. Attackers can query the full API schema including all types, queries, mutations, and fields — providing a complete roadmap for further attacks.`,
            severity: "high",
            endpoint: ep,
            method: "POST",
            payload: introspectionQuery,
            evidence: `Introspection response contains __schema data: ${body.substring(0, 300)}`,
            recommendation: "Disable GraphQL introspection in production. Use query depth limiting. Implement query complexity analysis. Add authentication to GraphQL endpoint.",
            cweId: "CWE-200",
            cvssScore: 7.5,
            aiAnalysis: "GraphQL introspection exposes the entire API surface. Attackers use this to discover hidden mutations, admin queries, and sensitive data fields that are not documented.",
          });

          // 2. Check for batch query attack
          const batchQuery = `[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]`;
          const batchRes = await fetchWithTimeout(ep, {
            method: "POST",
            headers: { "Content-Type": "application/json", "User-Agent": UA },
            body: batchQuery,
          }, 5000);

          if (batchRes.status === 200) {
            const batchBody = await batchRes.text();
            if (batchBody.startsWith("[")) {
              await addFinding(scanId, {
                type: "GraphQL",
                title: `GraphQL Batch Query Attack — DoS & Brute Force Risk`,
                description: `The GraphQL endpoint accepts batched queries (array of operations). Attackers can use this to bypass rate limiting by sending thousands of operations in a single HTTP request, enabling credential brute force or denial of service.`,
                severity: "medium",
                endpoint: ep,
                method: "POST",
                payload: batchQuery,
                evidence: `Batch query returned array response: ${batchBody.substring(0, 200)}`,
                recommendation: "Disable query batching or limit batch size to 5-10 operations. Implement per-operation rate limiting. Add query complexity scoring.",
                cweId: "CWE-770",
                cvssScore: 6.5,
              });
            }
          }

          // 3. Check for deeply nested query (DoS)
          const deepQuery = `{"query":"{user{posts{comments{author{posts{comments{author{name}}}}}}}}"}`;
          const deepRes = await fetchWithTimeout(ep, {
            method: "POST",
            headers: { "Content-Type": "application/json", "User-Agent": UA },
            body: deepQuery,
          }, 8000);

          if (deepRes.status === 200) {
            await addFinding(scanId, {
              type: "GraphQL",
              title: `GraphQL No Query Depth Limit — DoS via Nested Queries`,
              description: `The GraphQL endpoint does not enforce query depth limits. An attacker can craft deeply nested queries that cause exponential database load, leading to denial of service.`,
              severity: "medium",
              endpoint: ep,
              method: "POST",
              payload: deepQuery,
              evidence: `Deeply nested query (7 levels) returned HTTP ${deepRes.status}`,
              recommendation: "Implement query depth limiting (max 5-7 levels). Add query complexity analysis. Use query timeout. Consider persisted queries only in production.",
              cweId: "CWE-400",
              cvssScore: 5.9,
            });
          }
          return;
        }
      }
    } catch { }
  }
}

// ─── Built-in Proxy/Intruder Tool (Burp Suite Alternative) ───────────────────

export interface ProxyRequest {
  id: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  timestamp: number;
}

export interface IntruderResult {
  payload: string;
  statusCode: number;
  responseLength: number;
  responseTime: number;
  interesting: boolean;
  evidence?: string;
}

export async function runIntruder(
  targetUrl: string,
  method: string,
  headers: Record<string, string>,
  bodyTemplate: string,
  payloads: string[],
  insertionPoint: string
): Promise<IntruderResult[]> {
  const results: IntruderResult[] = [];

  for (const payload of payloads) {
    const body = bodyTemplate.replace(`§${insertionPoint}§`, payload);
    const start = Date.now();
    try {
      const res = await fetchWithTimeout(targetUrl, {
        method,
        headers: { ...headers, "User-Agent": UA },
        body: ["GET", "HEAD"].includes(method) ? undefined : body,
      }, 10000);
      const responseBody = await res.text();
      const elapsed = Date.now() - start;

      const interesting =
        // Different status from baseline (potential bypass)
        (res.status >= 200 && res.status < 300 && method === "POST") ||
        // Error messages indicating injection
        responseBody.toLowerCase().includes("sql") ||
        responseBody.toLowerCase().includes("syntax error") ||
        responseBody.toLowerCase().includes("mysql") ||
        responseBody.toLowerCase().includes("ora-") ||
        responseBody.toLowerCase().includes("postgresql") ||
        responseBody.toLowerCase().includes("exception") ||
        responseBody.toLowerCase().includes("stack trace") ||
        responseBody.toLowerCase().includes("warning:") ||
        // XSS reflection
        responseBody.includes(payload) ||
        // Time-based (SQLi sleep)
        elapsed > 4000 ||
        // Server errors
        res.status === 500 ||
        res.status === 503;

      results.push({
        payload,
        statusCode: res.status,
        responseLength: responseBody.length,
        responseTime: elapsed,
        interesting,
        evidence: interesting ? responseBody.substring(0, 200) : undefined,
      });
    } catch (err: any) {
      results.push({
        payload,
        statusCode: 0,
        responseLength: 0,
        responseTime: Date.now() - start,
        interesting: false,
      });
    }
  }

  return results;
}

// ─── Shodan-Enhanced Port Scan ────────────────────────────────────────────────

export async function checkOpenPorts(
  targetUrl: string,
  addFinding: Function,
  scanId: string
): Promise<void> {
  const hostname = new URL(targetUrl).hostname;

  // Try to resolve IP
  let ip = hostname;
  try {
    const dnsRes = await fetchWithTimeout(
      `https://dns.google/resolve?name=${hostname}&type=A`,
      { headers: { "User-Agent": UA } }, 5000
    );
    if (dnsRes.ok) {
      const data = await dnsRes.json() as Record<string, unknown>;
      const answers = data["Answer"] as Array<{ data: string }> || [];
      if (answers.length > 0) ip = answers[0].data;
    }
  } catch { }

  // Check Shodan
  const shodanResult = await queryShodan(ip);
  if (!shodanResult) return;

  // Report dangerous open ports
  const dangerousPorts: Record<number, { service: string; risk: string; sev: "critical" | "high" | "medium" }> = {
    21: { service: "FTP", risk: "Unencrypted file transfer, anonymous login possible", sev: "high" },
    22: { service: "SSH", risk: "Brute force target, key exposure risk", sev: "medium" },
    23: { service: "Telnet", risk: "Unencrypted remote access", sev: "critical" },
    25: { service: "SMTP", risk: "Open relay, spam abuse", sev: "high" },
    3306: { service: "MySQL", risk: "Database exposed to internet", sev: "critical" },
    5432: { service: "PostgreSQL", risk: "Database exposed to internet", sev: "critical" },
    6379: { service: "Redis", risk: "No auth by default, RCE possible", sev: "critical" },
    27017: { service: "MongoDB", risk: "No auth by default, data exposure", sev: "critical" },
    9200: { service: "Elasticsearch", risk: "No auth by default, full data access", sev: "critical" },
    8080: { service: "HTTP Alt", risk: "Dev server exposed, may lack security", sev: "medium" },
    8443: { service: "HTTPS Alt", risk: "Alternative HTTPS port exposed", sev: "medium" },
    4444: { service: "Metasploit", risk: "Possible backdoor/C2 channel", sev: "critical" },
    5900: { service: "VNC", risk: "Remote desktop exposed", sev: "critical" },
    3389: { service: "RDP", risk: "Remote desktop exposed, BlueKeep risk", sev: "critical" },
  };

  for (const port of shodanResult.ports) {
    const info = dangerousPorts[port];
    if (info) {
      await addFinding(scanId, {
        type: "Open Port",
        title: `Dangerous Port ${port} (${info.service}) Exposed to Internet`,
        description: `Shodan detected port ${port} (${info.service}) open on ${ip}. ${info.risk}. Services exposed to the internet are prime targets for automated exploitation.`,
        severity: info.sev,
        endpoint: `${ip}:${port}`,
        method: "TCP",
        evidence: `Shodan confirmed port ${port} open. Services: ${shodanResult.services.find(s => s.port === port)?.banner?.substring(0, 100) || "N/A"}`,
        recommendation: `Close port ${port} if not required. If required, restrict access via firewall to trusted IPs only. Enable authentication and encryption.`,
        cweId: "CWE-284",
        cvssScore: info.sev === "critical" ? 9.8 : info.sev === "high" ? 7.5 : 5.3,
        aiAnalysis: `Port ${port} (${info.service}) exposed to internet is a high-value target. Automated scanners continuously probe these ports for known vulnerabilities.`,
      });
    }
  }

  // Report known CVEs from Shodan
  for (const cve of shodanResult.vulns.slice(0, 5)) {
    await addFinding(scanId, {
      type: "Known CVE",
      title: `Known Vulnerability Detected: ${cve}`,
      description: `Shodan intelligence indicates the target host ${ip} is running software with known vulnerability ${cve}. This CVE has been publicly disclosed and exploit code may be available.`,
      severity: "critical",
      endpoint: ip,
      evidence: `Shodan CVE database match: ${cve} on ${ip} (${shodanResult.org})`,
      recommendation: `Immediately patch the affected software. Check the CVE database for specific remediation steps. Apply vendor security patches.`,
      cweId: "CWE-1035",
      cvssScore: 9.8,
      aiAnalysis: `Known CVEs with public exploits are the most dangerous findings. Automated exploit frameworks like Metasploit often have modules for these vulnerabilities.`,
    });
  }
}
