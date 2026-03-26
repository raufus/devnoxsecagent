import OpenAI from "openai";
import { db } from "@workspace/db";
import { aiDecisionsTable, findingsTable, scansTable } from "@workspace/db/schema";
import { eq } from "drizzle-orm";
import { randomUUID } from "crypto";
import { logger } from "./logger";

function getOpenAIClient() {
  const baseURL = process.env["AI_INTEGRATIONS_OPENAI_BASE_URL"];
  const apiKey = process.env["AI_INTEGRATIONS_OPENAI_API_KEY"] || "dummy";
  if (!baseURL) throw new Error("AI_INTEGRATIONS_OPENAI_BASE_URL not set");
  
  // Detect if using OpenRouter
  const isOpenRouter = baseURL.includes("openrouter.ai");
  const defaultHeaders = isOpenRouter ? {
    "HTTP-Referer": "https://devnoxsec.com",
    "X-Title": "DevNox Sec Agent"
  } : {};
  
  return new OpenAI({ 
    baseURL, 
    apiKey,
    defaultHeaders 
  });
}

// Get the appropriate model based on provider
function getModel() {
  const baseURL = process.env["AI_INTEGRATIONS_OPENAI_BASE_URL"] || "";
  // If using OpenRouter, use a free model
  if (baseURL.includes("openrouter.ai")) {
    // OpenRouter free models (verified working):
    // 1. "nvidia/nemotron-3-nano-30b-a3b:free" - Nvidia free (best, supports reasoning)
    // 2. "google/gemini-2.0-flash-exp:free" - Latest Gemini free
    // 3. "meta-llama/llama-3.2-3b-instruct:free" - Llama free
    return "nvidia/nemotron-3-nano-30b-a3b:free";
  }
  return "gpt-4o-mini"; // OpenAI default
}

export interface OrchestrationDecision {
  reasoning: string;
  decision: string;
  actions: Array<{ action: string; priority: number; reason: string }>;
  confidence: number;
}

export async function analyzeReconWithAI(
  scanId: string,
  targetDomain: string,
  reconSummary: {
    subdomainsFound: number;
    emailsFound: number;
    techStack: string[];
    cloudProviders: string[];
    ipCount: number;
    dnsRecordCount: number;
  }
): Promise<OrchestrationDecision> {
  const openai = getOpenAIClient();
  const prompt = `You are an expert penetration tester AI orchestrator. Analyze the recon results below and decide the next attack strategy.

Target: ${targetDomain}
Recon Results:
- Subdomains found: ${reconSummary.subdomainsFound}
- Email addresses found: ${reconSummary.emailsFound}
- Tech stack: ${reconSummary.techStack.join(", ") || "Unknown"}
- Cloud providers: ${reconSummary.cloudProviders.join(", ") || "None detected"}
- IP addresses: ${reconSummary.ipCount}
- DNS records: ${reconSummary.dnsRecordCount}

Based on this intelligence, provide:
1. Your reasoning about the attack surface
2. A concrete decision on what vulnerability types to prioritize
3. A list of up to 5 specific actions with priorities (1=highest)
4. Confidence level (0-100)

Respond in JSON format:
{
  "reasoning": "...",
  "decision": "...",
  "actions": [{"action": "...", "priority": 1, "reason": "..."}],
  "confidence": 85
}`;

  try {
    const response = await openai.chat.completions.create({
      model: getModel(),
      max_completion_tokens: 1024,
      messages: [{ role: "user", content: prompt }],
      response_format: { type: "json_object" },
    });

    const content = response.choices[0]?.message?.content || "{}";
    const parsed = JSON.parse(content) as OrchestrationDecision;

    await db.insert(aiDecisionsTable).values({
      id: randomUUID(),
      scanId,
      phase: "recon",
      input: JSON.stringify(reconSummary),
      reasoning: parsed.reasoning || "Analysis complete",
      decision: parsed.decision || "Proceed with standard scan",
      actions: parsed.actions || [],
      confidence: parsed.confidence || 75,
    });

    return parsed;
  } catch (err) {
    logger.warn({ err }, "AI recon analysis failed — no fallback, skipping AI decision");
    return {
      reasoning: "AI analysis unavailable — OpenAI API key not configured or request failed.",
      decision: "Proceeding with standard full vulnerability scan.",
      actions: [],
      confidence: 0,
    };
  }
}

export async function generateAIExploitPayloads(
  scanId: string,
  finding: {
    type: string;
    title: string;
    endpoint: string;
    parameter?: string;
    evidence?: string;
  }
): Promise<string[]> {
  const openai = getOpenAIClient();

  const prompt = `You are an expert security researcher. Generate 3-5 advanced exploit payloads for the following vulnerability:

Vulnerability Type: ${finding.type}
Title: ${finding.title}
Endpoint: ${finding.endpoint}
Parameter: ${finding.parameter || "N/A"}
Evidence: ${finding.evidence || "N/A"}

Generate contextually appropriate payloads that an attacker might use. Include encoded variants and bypass techniques.
Respond in JSON: {"payloads": ["payload1", "payload2", ...]}`;

  try {
    const response = await openai.chat.completions.create({
      model: getModel(),
      max_completion_tokens: 512,
      messages: [{ role: "user", content: prompt }],
      response_format: { type: "json_object" },
    });

    const content = response.choices[0]?.message?.content || '{"payloads":[]}';
    const parsed = JSON.parse(content) as { payloads: string[] };
    return parsed.payloads || [];
  } catch {
    return [];
  }
}

export async function analyzeVulnerabilitiesWithAI(
  scanId: string,
  findings: Array<{
    type: string;
    title: string;
    severity: string;
    endpoint: string;
    description: string;
  }>
): Promise<{ riskScore: number; attackChains: string[]; executiveSummary: string; prioritizedActions: string[] }> {
  const openai = getOpenAIClient();

  const findingsSummary = findings.slice(0, 15).map(f => `- [${f.severity.toUpperCase()}] ${f.type}: ${f.title} at ${f.endpoint}`).join("\n");

  const prompt = `You are a senior penetration tester writing an executive security assessment.

Findings discovered:
${findingsSummary}

Total: ${findings.length} vulnerabilities (${findings.filter(f => f.severity === "critical").length} critical, ${findings.filter(f => f.severity === "high").length} high)

Provide:
1. Overall risk score (0-100)
2. Potential attack chains (how vulnerabilities can be chained together)
3. Executive summary (2-3 sentences)
4. Top 5 prioritized remediation actions

Respond in JSON:
{
  "riskScore": 75,
  "attackChains": ["Chain 1: ...", "Chain 2: ..."],
  "executiveSummary": "...",
  "prioritizedActions": ["Action 1", "Action 2", ...]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: getModel(),
      max_completion_tokens: 1024,
      messages: [{ role: "user", content: prompt }],
      response_format: { type: "json_object" },
    });

    const content = response.choices[0]?.message?.content || "{}";
    const parsed = JSON.parse(content) as { riskScore: number; attackChains: string[]; executiveSummary: string; prioritizedActions: string[] };

    await db.insert(aiDecisionsTable).values({
      id: randomUUID(),
      scanId,
      phase: "ai_analysis",
      input: `${findings.length} findings`,
      reasoning: `Analyzed ${findings.length} vulnerabilities for attack chains and risk scoring`,
      decision: `Risk Score: ${parsed.riskScore}/100`,
      actions: (parsed.prioritizedActions || []).map((a, i) => ({ action: a, priority: i + 1, reason: "AI prioritized" })),
      confidence: 85,
    });

    return parsed;
  } catch (err) {
    logger.warn({ err }, "AI vulnerability analysis failed — no fallback");
    const criticalCount = findings.filter(f => f.severity === "critical").length;
    const highCount = findings.filter(f => f.severity === "high").length;
    const riskScore = Math.min(100, criticalCount * 15 + highCount * 8 + findings.length * 2);
    return {
      riskScore,
      attackChains: [],
      executiveSummary: `${findings.length} vulnerabilities found (${criticalCount} critical, ${highCount} high). AI analysis unavailable — configure OpenAI API key for detailed analysis.`,
      prioritizedActions: [],
    };
  }
}

export async function getAIDecisions(scanId: string) {
  return db.select().from(aiDecisionsTable).where(eq(aiDecisionsTable.scanId, scanId)).orderBy(aiDecisionsTable.createdAt);
}
