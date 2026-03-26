import { useParams } from "wouter";
import { useGetScanRecon, useGetScan } from "@workspace/api-client-react";
import { Layout } from "@/components/layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Globe, Server, Mail, Network, Shield, Database, Users, Wifi } from "lucide-react";import { parseJsonField } from "@/lib/utils";

function InfoRow({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex justify-between items-start py-1.5 border-b border-primary/10 last:border-0">
      <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider">{label}</span>
      <span className="text-xs font-mono text-foreground ml-4 text-right max-w-[200px] break-all">{value || "—"}</span>
    </div>
  );
}

export default function ReconPage() {
  const { id } = useParams();
  const { data: scanData } = useGetScan(id!);
  const { data, isLoading } = useGetScanRecon(id!);

  const recon = data?.reconData;

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
            <h1 className="text-2xl font-display font-bold">RECON_INTELLIGENCE</h1>
            <p className="text-xs font-mono text-muted-foreground mt-1">OSINT • DNS • WHOIS • EMAIL HARVEST • SUBDOMAIN ENUM</p>
          </div>
        </header>

        {isLoading && (
          <div className="flex items-center gap-3 p-8 justify-center font-mono text-sm text-muted-foreground">
            <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            LOADING INTELLIGENCE DATA...
          </div>
        )}

        {!isLoading && !recon && (
          <div className="p-8 text-center">
            <Shield className="w-12 h-12 text-muted-foreground mx-auto mb-3 opacity-40" />
            <p className="font-mono text-sm text-muted-foreground">No recon data available yet.</p>
            <p className="font-mono text-xs text-muted-foreground mt-1">Run a Full or Deep scan to collect OSINT intelligence.</p>
          </div>
        )}

        {recon && (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {/* Network Info */}
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-mono flex items-center gap-2 text-cyan-400">
                  <Network className="w-4 h-4" />
                  NETWORK_MAP
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1">
                {(() => {
                  const ips = parseJsonField<string[]>(recon.ipAddresses, []);
                  const net = parseJsonField<{ asn?: string; org?: string; country?: string; range?: string }>(recon.networkInfo, {});
                  const clouds = parseJsonField<string[]>(recon.cloudProviders, []);
                  return <>
                    <InfoRow label="Domain" value={recon.targetDomain || "—"} />
                    <InfoRow label="IPs" value={ips.join(", ") || "None"} />
                    <InfoRow label="ASN" value={net?.asn || "—"} />
                    <InfoRow label="Organization" value={net?.org || "—"} />
                    <InfoRow label="Country" value={net?.country || "—"} />
                    <InfoRow label="IP Range" value={net?.range || "—"} />
                    {clouds.length > 0 && (
                      <div className="pt-2 flex flex-wrap gap-1">
                        {clouds.map(p => (
                          <Badge key={p} className="text-[10px] bg-blue-500/20 text-blue-400 border-blue-400/30">{p}</Badge>
                        ))}
                      </div>
                    )}
                  </>;
                })()}
              </CardContent>
            </Card>

            {/* DNS Records */}
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-mono flex items-center gap-2 text-yellow-400">
                  <Database className="w-4 h-4" />
                  DNS_RECORDS ({parseJsonField<Array<{type: string; value: string}>>(recon.dnsRecords, []).length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1 max-h-56 overflow-y-auto pr-1">
                  {parseJsonField<Array<{type: string; value: string}>>(recon.dnsRecords, []).length === 0 ? (
                    <p className="text-xs font-mono text-muted-foreground">No DNS records found</p>
                  ) : (
                    parseJsonField<Array<{type: string; value: string}>>(recon.dnsRecords, []).map((r, i) => (
                      <div key={i} className="flex items-start gap-2 py-1 border-b border-primary/10">
                        <Badge className="text-[9px] shrink-0 bg-yellow-500/20 text-yellow-400 border-yellow-400/30 font-mono">{r.type}</Badge>
                        <span className="text-xs font-mono text-foreground break-all">{r.value}</span>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>

            {/* WHOIS Data */}
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-mono flex items-center gap-2 text-green-400">
                  <Globe className="w-4 h-4" />
                  WHOIS_DATA
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1">
                {Object.entries(parseJsonField<Record<string, string>>(recon.whoisData, {})).length === 0 ? (
                  <p className="text-xs font-mono text-muted-foreground">WHOIS data unavailable</p>
                ) : (
                  Object.entries(parseJsonField<Record<string, string>>(recon.whoisData, {})).slice(0, 8).map(([key, value]) => (
                    <InfoRow key={key} label={key} value={value?.toString().substring(0, 60)} />
                  ))
                )}
              </CardContent>
            </Card>

            {/* Subdomains */}
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm md:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-mono flex items-center gap-2 text-orange-400">
                  <Server className="w-4 h-4" />
                  SUBDOMAINS ({parseJsonField<Array<{name: string; ip?: string; status?: string}>>(recon.subdomains, []).length} found)
                </CardTitle>
              </CardHeader>
              <CardContent>
                {parseJsonField<Array<{name: string; ip?: string; status?: string}>>(recon.subdomains, []).length === 0 ? (
                  <p className="text-xs font-mono text-muted-foreground">No subdomains discovered</p>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-60 overflow-y-auto pr-1">
                    {parseJsonField<Array<{name: string; ip?: string; status?: string}>>(recon.subdomains, []).map((sub, i) => (
                      <div key={i} className="flex items-center justify-between p-2 border border-primary/10 bg-primary/5 rounded font-mono text-xs">
                        <span className="text-orange-400">{sub.name}</span>
                        <div className="flex items-center gap-2">
                          {sub.ip && <span className="text-muted-foreground">{sub.ip}</span>}
                          <div className="w-1.5 h-1.5 rounded-full bg-green-400 shadow-[0_0_4px_#4ade80]" />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Email Addresses */}
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-mono flex items-center gap-2 text-purple-400">
                  <Mail className="w-4 h-4" />
                  EMAIL_HARVEST ({parseJsonField<string[]>(recon.emails, []).length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                {parseJsonField<string[]>(recon.emails, []).length === 0 ? (
                  <p className="text-xs font-mono text-muted-foreground">No emails harvested</p>
                ) : (
                  <div className="space-y-1 max-h-56 overflow-y-auto">
                    {parseJsonField<string[]>(recon.emails, []).map((email, i) => (
                      <div key={i} className="py-1 px-2 border-b border-primary/10 font-mono text-xs text-purple-300">{email}</div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Tech Stack */}
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-mono flex items-center gap-2 text-primary">
                  <Wifi className="w-4 h-4" />
                  TECH_STACK
                </CardTitle>
              </CardHeader>
              <CardContent>
                {parseJsonField<string[]>(recon.techStack, []).length === 0 ? (
                  <p className="text-xs font-mono text-muted-foreground">Tech stack not detected</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {parseJsonField<string[]>(recon.techStack, []).map((tech, i) => (
                      <Badge key={i} className="text-xs bg-primary/20 text-primary border-primary/30">{tech}</Badge>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Open Ports */}
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-mono flex items-center gap-2 text-red-400">
                  <Server className="w-4 h-4" />
                  OPEN_PORTS ({parseJsonField<Array<{port: number; service: string; banner?: string}>>(recon.openPorts, []).length} found)
                </CardTitle>
              </CardHeader>
              <CardContent>
                {parseJsonField<Array<{port: number; service: string; banner?: string}>>(recon.openPorts, []).length === 0 ? (
                  <p className="text-xs font-mono text-muted-foreground">No open ports detected</p>
                ) : (
                  <div className="space-y-1 max-h-56 overflow-y-auto">
                    {parseJsonField<Array<{port: number; service: string; banner?: string}>>(recon.openPorts, []).map((p, i) => (
                      <div key={i} className="flex items-center justify-between py-1 px-2 border-b border-primary/10">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs text-red-400 font-bold w-12">{p.port}</span>
                          <Badge className="text-[9px] bg-orange-500/20 text-orange-400 border-orange-400/30">{p.service}</Badge>
                        </div>
                        {p.banner && <span className="font-mono text-[9px] text-muted-foreground truncate max-w-[120px]">{p.banner}</span>}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-mono flex items-center gap-2 text-pink-400">
                  <Users className="w-4 h-4" />
                  SOCIAL_FOOTPRINT
                </CardTitle>
              </CardHeader>
              <CardContent>
                {parseJsonField<Array<{platform: string; url: string}>>(recon.socialProfiles, []).length === 0 ? (
                  <p className="text-xs font-mono text-muted-foreground">No social profiles found</p>
                ) : (
                  <div className="space-y-1">
                    {parseJsonField<Array<{platform: string; url: string}>>(recon.socialProfiles, []).map((profile, i) => (
                      <div key={i} className="flex items-center justify-between py-1 border-b border-primary/10">
                        <span className="text-xs font-mono text-pink-400">{profile.platform}</span>
                        <a href={profile.url} target="_blank" rel="noopener noreferrer" className="text-xs font-mono text-muted-foreground hover:text-primary truncate max-w-[140px]">{profile.url}</a>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </Layout>
  );
}
