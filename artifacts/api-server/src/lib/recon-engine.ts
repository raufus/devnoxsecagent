import { db } from "@workspace/db";
import { reconDataTable, graphNodesTable, graphEdgesTable } from "@workspace/db/schema";
import { eq } from "drizzle-orm";
import { randomUUID } from "crypto";
import dns from "dns/promises";
import net from "net";
import { logger } from "./logger";

async function fetchWithTimeout(url: string, opts: RequestInit = {}, timeoutMs = 6000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

// ─── TCP Port Scanner ─────────────────────────────────────────────────────────

const PORT_SERVICES: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
  465: "SMTPS", 587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S",
  1433: "MSSQL", 1521: "Oracle DB", 2181: "Zookeeper", 2375: "Docker",
  3000: "Node.js/Dev", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
  5000: "Flask/Dev", 5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC",
  6379: "Redis", 7001: "WebLogic", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
  8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "PHP-FPM", 9090: "Prometheus",
  9200: "Elasticsearch", 9300: "Elasticsearch-Cluster", 11211: "Memcached",
  27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB-Web",
};

async function checkPort(host: string, port: number, timeoutMs = 2000): Promise<{ open: boolean; banner?: string }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = "";
    let resolved = false;

    const done = (open: boolean) => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve({ open, banner: banner.substring(0, 100).trim() || undefined });
      }
    };

    socket.setTimeout(timeoutMs);
    socket.on("connect", () => {
      // Try to grab banner
      socket.write("HEAD / HTTP/1.0\r\n\r\n");
    });
    socket.on("data", (data) => {
      banner += data.toString();
      done(true);
    });
    socket.on("timeout", () => done(false));
    socket.on("error", () => done(false));
    socket.on("close", () => done(socket.destroyed ? false : true));

    // If no data after 1s, still mark as open
    socket.on("connect", () => {
      setTimeout(() => done(true), 1000);
    });

    try {
      socket.connect(port, host);
    } catch {
      done(false);
    }
  });
}

async function scanPorts(host: string): Promise<Array<{ port: number; service: string; banner?: string }>> {
  const portsToScan = Object.keys(PORT_SERVICES).map(Number);
  const results: Array<{ port: number; service: string; banner?: string }> = [];

  // Scan in batches of 20 concurrent
  const batchSize = 20;
  for (let i = 0; i < portsToScan.length; i += batchSize) {
    const batch = portsToScan.slice(i, i + batchSize);
    const checks = batch.map(async (port) => {
      const result = await checkPort(host, port, 1500);
      if (result.open) {
        results.push({
          port,
          service: PORT_SERVICES[port] || "Unknown",
          banner: result.banner,
        });
      }
    });
    await Promise.allSettled(checks);
  }

  return results.sort((a, b) => a.port - b.port);
}

export interface ReconResult {
  targetDomain: string;
  ipAddresses: string[];
  subdomains: Array<{ name: string; ip?: string; status?: string }>;
  dnsRecords: Array<{ type: string; value: string }>;
  whoisData: Record<string, string>;
  emails: string[];
  socialProfiles: Array<{ platform: string; url: string }>;
  techStack: string[];
  openPorts: Array<{ port: number; service: string; banner?: string }>;
  cloudProviders: string[];
  networkInfo: { asn?: string; org?: string; country?: string; range?: string };
}

async function resolveDNS(domain: string): Promise<{ ipAddresses: string[]; dnsRecords: Array<{ type: string; value: string }> }> {
  const ipAddresses: string[] = [];
  const dnsRecords: Array<{ type: string; value: string }> = [];

  try {
    const aRecords = await dns.resolve4(domain).catch(() => []);
    for (const ip of aRecords) {
      ipAddresses.push(ip);
      dnsRecords.push({ type: "A", value: ip });
    }
    const aaaaRecords = await dns.resolve6(domain).catch(() => []);
    for (const ip of aaaaRecords) {
      ipAddresses.push(ip);
      dnsRecords.push({ type: "AAAA", value: ip });
    }
    const mxRecords = await dns.resolveMx(domain).catch(() => []);
    for (const mx of mxRecords) {
      dnsRecords.push({ type: "MX", value: `${mx.priority} ${mx.exchange}` });
    }
    const txtRecords = await dns.resolveTxt(domain).catch(() => []);
    for (const txt of txtRecords) {
      dnsRecords.push({ type: "TXT", value: txt.join(" ") });
    }
    const nsRecords = await dns.resolveNs(domain).catch(() => []);
    for (const ns of nsRecords) {
      dnsRecords.push({ type: "NS", value: ns });
    }
    const cnameRecords = await dns.resolveCname(domain).catch(() => []);
    for (const cname of cnameRecords) {
      dnsRecords.push({ type: "CNAME", value: cname });
    }
  } catch { }

  return { ipAddresses: [...new Set(ipAddresses)], dnsRecords };
}

async function getNetworkInfo(ip: string): Promise<{ asn?: string; org?: string; country?: string; range?: string }> {
  try {
    const res = await fetchWithTimeout(`https://ipapi.co/${ip}/json/`, {
      headers: { "User-Agent": "AutoPentest-AI/1.0" },
    }, 5000);
    if (res.ok) {
      const data = await res.json() as Record<string, unknown>;
      return {
        asn: data["asn"] as string,
        org: data["org"] as string,
        country: data["country_name"] as string,
        range: data["network"] as string,
      };
    }
  } catch { }
  return {};
}

async function fetchWhois(domain: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};

  // Source 1: RDAP.org
  try {
    const res = await fetchWithTimeout(`https://rdap.org/domain/${domain}`, {
      headers: { "Accept": "application/json", "User-Agent": "AutoPentest-AI/1.0" },
    }, 8000);
    if (res.ok) {
      const data = await res.json() as Record<string, unknown>;
      if (data["events"]) {
        const events = data["events"] as Array<{ eventAction: string; eventDate: string }>;
        for (const ev of events) {
          if (ev.eventAction === "registration") result["Registered On"] = new Date(ev.eventDate).toLocaleDateString();
          if (ev.eventAction === "expiration") result["Expires On"] = new Date(ev.eventDate).toLocaleDateString();
          if (ev.eventAction === "last changed") result["Updated On"] = new Date(ev.eventDate).toLocaleDateString();
        }
      }
      if (data["entities"]) {
        const entities = data["entities"] as Array<{ roles: string[]; vcardArray?: unknown[]; handle?: string }>;
        for (const entity of entities) {
          if (entity.roles?.includes("registrar") && entity.handle) {
            result["Registrar"] = entity.handle;
          }
          if (entity.roles?.includes("registrant")) {
            const vcard = entity.vcardArray as unknown[][];
            if (vcard && vcard[1]) {
              for (const field of vcard[1] as unknown[][]) {
                if (field[0] === "org") result["Registrant Org"] = String(field[3] || "");
                if (field[0] === "email") result["Registrant Email"] = String(field[3] || "");
                if (field[0] === "country") result["Country"] = String(field[3] || "");
              }
            }
          }
        }
      }
      if (data["nameservers"]) {
        const ns = data["nameservers"] as Array<{ ldhName: string }>;
        result["Nameservers"] = ns.map(n => n.ldhName).join(", ");
      }
      if (data["status"]) {
        result["Status"] = (data["status"] as string[]).join(", ");
      }
      if (data["handle"]) result["Domain ID"] = data["handle"] as string;
    }
  } catch { }

  // Source 2: whois.iana.org for TLD info (fallback)
  if (Object.keys(result).length === 0) {
    try {
      const tld = domain.split(".").pop() || "";
      const res = await fetchWithTimeout(`https://www.iana.org/domains/root/db/${tld}.html`, {
        headers: { "User-Agent": "AutoPentest-AI/1.0" },
      }, 5000);
      if (res.ok) {
        result["TLD"] = `.${tld}`;
        result["Registry"] = "IANA Registry";
      }
    } catch { }
  }

  // Source 3: ipwhois.io for IP-based info
  try {
    const dnsRes = await fetchWithTimeout(`https://dns.google/resolve?name=${domain}&type=A`, {
      headers: { "User-Agent": "AutoPentest-AI/1.0" },
    }, 5000);
    if (dnsRes.ok) {
      const dnsData = await dnsRes.json() as Record<string, unknown>;
      const answers = dnsData["Answer"] as Array<{ data: string }> || [];
      if (answers.length > 0) {
        const ip = answers[0].data;
        result["Resolved IP"] = ip;
        const ipRes = await fetchWithTimeout(`https://ipwhois.app/json/${ip}`, {
          headers: { "User-Agent": "AutoPentest-AI/1.0" },
        }, 5000);
        if (ipRes.ok) {
          const ipData = await ipRes.json() as Record<string, unknown>;
          if (ipData["org"]) result["Organization"] = ipData["org"] as string;
          if (ipData["country"]) result["Country"] = ipData["country"] as string;
          if (ipData["isp"]) result["ISP"] = ipData["isp"] as string;
          if (ipData["asn"]) result["ASN"] = ipData["asn"] as string;
          if (ipData["timezone"]) result["Timezone"] = ipData["timezone"] as string;
          if (ipData["city"]) result["City"] = ipData["city"] as string;
        }
      }
    }
  } catch { }

  return result;
}

async function enumerateSubdomains(domain: string): Promise<Array<{ name: string; ip?: string; status?: string }>> {
  const commonSubs = [
    "www", "api", "admin", "dev", "staging", "test", "mail", "smtp", "ftp",
    "vpn", "remote", "portal", "dashboard", "app", "beta", "internal", "ops",
    "cdn", "static", "assets", "media", "img", "images", "auth", "login",
    "secure", "mobile", "m", "shop", "store", "support", "help", "blog",
    "status", "monitor", "metrics", "grafana", "jenkins", "gitlab", "jira",
    "ns1", "ns2", "mx", "smtp2", "mail2", "webmail", "autodiscover",
    "cloud", "git", "svn", "ftp2", "backup", "old", "new", "demo", "pay",
    "api2", "api-dev", "v1", "v2", "prod", "production", "qa", "uat",
    "search", "web", "vpn2", "proxy", "gateway", "lb", "load", "test2",
  ];

  const found: Array<{ name: string; ip?: string; status?: string }> = [];
  const checks = commonSubs.map(async (sub) => {
    const fqdn = `${sub}.${domain}`;
    try {
      const ips = await dns.resolve4(fqdn).catch(() => null);
      if (ips && ips.length > 0) {
        found.push({ name: fqdn, ip: ips[0], status: "active" });
      }
    } catch { }
  });
  await Promise.allSettled(checks);
  return found;
}

async function harvestEmails(targetUrl: string, domain: string): Promise<string[]> {
  const emails = new Set<string>();
  const emailRe = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

  const urlsToCheck = [
    targetUrl,
    `${new URL(targetUrl).origin}/about`,
    `${new URL(targetUrl).origin}/contact`,
    `${new URL(targetUrl).origin}/team`,
    `${new URL(targetUrl).origin}/staff`,
  ];

  for (const url of urlsToCheck) {
    try {
      const res = await fetchWithTimeout(url, {}, 5000);
      const body = await res.text();
      const found = body.match(emailRe) || [];
      for (const email of found) {
        if (!email.includes("example.") && !email.includes("test@") && !email.includes("sentry") && !email.includes("placeholder")) {
          emails.add(email.toLowerCase());
        }
      }
    } catch { }
  }
  return [...emails].slice(0, 20);
}

async function detectCloudProvider(ipAddresses: string[], dnsRecords: Array<{ type: string; value: string }>, domain: string): Promise<string[]> {
  const providers: string[] = [];
  const allText = [...ipAddresses, ...dnsRecords.map(r => r.value), domain].join(" ").toLowerCase();

  if (allText.includes("amazonaws") || allText.includes("cloudfront") || allText.includes("elasticbeanstalk") || allText.includes("ec2")) {
    providers.push("AWS");
  }
  if (allText.includes("azure") || allText.includes("microsoft") || allText.includes("windows.net")) {
    providers.push("Azure");
  }
  if (allText.includes("google") || allText.includes("googleapis") || allText.includes("cloud.google")) {
    providers.push("GCP");
  }
  if (allText.includes("cloudflare")) {
    providers.push("Cloudflare");
  }
  if (allText.includes("fastly")) {
    providers.push("Fastly");
  }
  if (allText.includes("heroku") || allText.includes("herokudns")) {
    providers.push("Heroku");
  }
  if (allText.includes("vercel") || allText.includes("now.sh")) {
    providers.push("Vercel");
  }
  if (allText.includes("netlify")) {
    providers.push("Netlify");
  }

  return [...new Set(providers)];
}

async function detectSocialProfiles(domain: string): Promise<Array<{ platform: string; url: string }>> {
  const profiles: Array<{ platform: string; url: string }> = [];

  const platforms = [
    { name: "GitHub", url: `https://github.com/${domain.split(".")[0]}` },
    { name: "LinkedIn", url: `https://www.linkedin.com/company/${domain.split(".")[0]}` },
    { name: "Twitter/X", url: `https://twitter.com/${domain.split(".")[0]}` },
    { name: "Facebook", url: `https://www.facebook.com/${domain.split(".")[0]}` },
  ];

  for (const platform of platforms) {
    try {
      const res = await fetchWithTimeout(platform.url, { redirect: "follow" }, 4000);
      if (res.status === 200) {
        profiles.push({ platform: platform.name, url: platform.url });
      }
    } catch { }
  }

  return profiles;
}

async function detectTechStack(targetUrl: string): Promise<string[]> {
  const stack: string[] = [];
  try {
    const res = await fetchWithTimeout(targetUrl, { redirect: "follow" });
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
    if (html.includes("react")) stack.push("React");
    if (html.includes("laravel") || html.includes("csrf-token")) stack.push("Laravel");
    if (html.includes("csrfmiddlewaretoken")) stack.push("Django");
    if (html.includes("authenticity_token")) stack.push("Ruby on Rails");
    if (html.includes("jquery")) stack.push("jQuery");
    if (html.includes("bootstrap")) stack.push("Bootstrap");
    if (headers["x-shopify-stage"] || html.includes("shopify")) stack.push("Shopify");
    if (html.includes("wix")) stack.push("Wix");
  } catch { }
  return [...new Set(stack.filter(Boolean))].slice(0, 15);
}

export async function runReconEngine(targetUrl: string, scanId: string): Promise<ReconResult> {
  const parsed = new URL(targetUrl);
  const domain = parsed.hostname;

  logger.info({ domain, scanId }, "Starting recon engine");

  const [dnsResult, subdomains, emails, techStack, socialProfiles] = await Promise.allSettled([
    resolveDNS(domain),
    enumerateSubdomains(domain),
    harvestEmails(targetUrl, domain),
    detectTechStack(targetUrl),
    detectSocialProfiles(domain),
  ]);

  const dns_result = dnsResult.status === "fulfilled" ? dnsResult.value : { ipAddresses: [], dnsRecords: [] };
  const subs = subdomains.status === "fulfilled" ? subdomains.value : [];
  const emailList = emails.status === "fulfilled" ? emails.value : [];
  const tech = techStack.status === "fulfilled" ? techStack.value : [];
  const socials = socialProfiles.status === "fulfilled" ? socialProfiles.value : [];

  const [networkInfo, whoisData, cloudProviders] = await Promise.allSettled([
    dns_result.ipAddresses[0] ? getNetworkInfo(dns_result.ipAddresses[0]) : Promise.resolve({}),
    fetchWhois(domain),
    detectCloudProvider(dns_result.ipAddresses, dns_result.dnsRecords, domain),
  ]);

  // Port scan the primary IP
  let openPorts: Array<{ port: number; service: string; banner?: string }> = [];
  if (dns_result.ipAddresses[0]) {
    logger.info({ host: dns_result.ipAddresses[0] }, "Starting port scan");
    try {
      openPorts = await scanPorts(dns_result.ipAddresses[0]);
      logger.info({ host: dns_result.ipAddresses[0], openPorts: openPorts.length }, "Port scan complete");
    } catch (err) {
      logger.warn({ err }, "Port scan failed");
    }
  }
  const result: ReconResult = {
    targetDomain: domain,
    ipAddresses: dns_result.ipAddresses,
    subdomains: subs,
    dnsRecords: dns_result.dnsRecords,
    whoisData: whoisData.status === "fulfilled" ? whoisData.value : {},
    emails: emailList,
    socialProfiles: socials,
    techStack: tech,
    openPorts: openPorts,
    cloudProviders: cloudProviders.status === "fulfilled" ? cloudProviders.value : [],
    networkInfo: networkInfo.status === "fulfilled" ? networkInfo.value : {},
  };

  // Save to DB
  await db.insert(reconDataTable).values({
    id: randomUUID(),
    scanId,
    targetDomain: domain,
    ipAddresses: result.ipAddresses,
    subdomains: result.subdomains,
    dnsRecords: result.dnsRecords,
    whoisData: result.whoisData,
    emails: result.emails,
    socialProfiles: result.socialProfiles,
    techStack: result.techStack,
    openPorts: result.openPorts,
    cloudProviders: result.cloudProviders,
    networkInfo: result.networkInfo,
  });

  return result;
}

export async function buildAttackGraph(scanId: string, reconResult: ReconResult, findings: Array<{ id: string; type: string; title: string; severity: string; endpoint: string }>): Promise<void> {
  const nodes: Array<typeof graphNodesTable.$inferInsert> = [];
  const edges: Array<typeof graphEdgesTable.$inferInsert> = [];

  const domainNodeId = randomUUID();
  nodes.push({
    id: domainNodeId,
    scanId,
    nodeType: "domain",
    label: reconResult.targetDomain,
    data: { whois: reconResult.whoisData, cloudProviders: reconResult.cloudProviders },
    severity: "none",
  });

  for (const ip of reconResult.ipAddresses.slice(0, 5)) {
    const ipNodeId = randomUUID();
    nodes.push({
      id: ipNodeId,
      scanId,
      nodeType: "ip",
      label: ip,
      data: { networkInfo: reconResult.networkInfo },
      severity: "none",
    });
    edges.push({
      id: randomUUID(),
      scanId,
      sourceId: domainNodeId,
      targetId: ipNodeId,
      edgeType: "resolves_to",
      label: "resolves to",
    });
  }

  for (const sub of reconResult.subdomains.slice(0, 10)) {
    const subNodeId = randomUUID();
    nodes.push({
      id: subNodeId,
      scanId,
      nodeType: "subdomain",
      label: sub.name,
      data: { ip: sub.ip, status: sub.status },
      severity: "none",
    });
    edges.push({
      id: randomUUID(),
      scanId,
      sourceId: domainNodeId,
      targetId: subNodeId,
      edgeType: "has_subdomain",
      label: "subdomain",
    });
  }

  if (reconResult.techStack.length > 0) {
    const serverNodeId = randomUUID();
    nodes.push({
      id: serverNodeId,
      scanId,
      nodeType: "server",
      label: reconResult.techStack.slice(0, 3).join(" / "),
      data: { techStack: reconResult.techStack },
      severity: "none",
    });
    if (reconResult.ipAddresses.length > 0) {
      const firstIpNode = nodes.find(n => n.nodeType === "ip");
      if (firstIpNode) {
        edges.push({
          id: randomUUID(),
          scanId,
          sourceId: firstIpNode.id,
          targetId: serverNodeId,
          edgeType: "runs",
          label: "runs",
        });
      }
    }

    const serverNodeRef = serverNodeId;
    const criticalFindings = findings.filter(f => f.severity === "critical" || f.severity === "high").slice(0, 8);
    for (const finding of criticalFindings) {
      const vulnNodeId = randomUUID();
      nodes.push({
        id: vulnNodeId,
        scanId,
        nodeType: "vulnerability",
        label: finding.title.substring(0, 40),
        data: { type: finding.type, endpoint: finding.endpoint, findingId: finding.id },
        severity: finding.severity as "critical" | "high" | "medium" | "low" | "info",
      });
      edges.push({
        id: randomUUID(),
        scanId,
        sourceId: serverNodeRef,
        targetId: vulnNodeId,
        edgeType: "vulnerable_to",
        label: finding.type,
      });

      if (finding.severity === "critical") {
        const exploitNodeId = randomUUID();
        nodes.push({
          id: exploitNodeId,
          scanId,
          nodeType: "exploit",
          label: `Exploit: ${finding.type}`,
          data: { targetFindingId: finding.id, attackType: finding.type },
          severity: "critical",
        });
        edges.push({
          id: randomUUID(),
          scanId,
          sourceId: vulnNodeId,
          targetId: exploitNodeId,
          edgeType: "exploited_via",
          label: "can be exploited",
        });
      }
    }
  }

  if (nodes.length > 0) {
    await db.insert(graphNodesTable).values(nodes);
  }
  if (edges.length > 0) {
    await db.insert(graphEdgesTable).values(edges);
  }
}
