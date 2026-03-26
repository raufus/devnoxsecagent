import { useState, useEffect } from 'react';
import { useParams, Link } from 'wouter';
import { Layout } from '@/components/layout';
import { ChevronLeft, Play, Shield, Zap, Brain, Link2, Target, FileJson } from 'lucide-react';
import { cn } from '@/lib/utils';
import { APITestTab } from '@/components/APITestTab';

type TabType = 'validate' | 'exploit' | 'bypass' | 'ai' | 'chains' | 'profile' | 'api-test';

export default function AdvancedAnalysis() {
  const { id } = useParams();
  const [activeTab, setActiveTab] = useState<TabType>('validate');

  const tabs = [
    { id: 'validate' as TabType, label: 'Validation Engine', icon: Shield },
    { id: 'exploit' as TabType, label: 'Exploitation', icon: Zap },
    { id: 'bypass' as TabType, label: 'WAF Bypass', icon: Shield },
    { id: 'ai' as TabType, label: 'AI Attack Plan', icon: Brain },
    { id: 'chains' as TabType, label: 'Vuln Chains', icon: Link2 },
    { id: 'profile' as TabType, label: 'Target Profile', icon: Target },
    { id: 'api-test' as TabType, label: 'API Testing', icon: FileJson },
  ];

  return (
    <Layout>
      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="flex items-center gap-3 mb-6">
          <Link href={`/scans/${id}/report`}>
            <button className="p-2 hover:bg-gray-800 rounded-lg transition-colors">
              <ChevronLeft className="w-5 h-5" />
            </button>
          </Link>
          <div>
            <h1 className="text-2xl font-bold font-mono flex items-center gap-2">
              <Zap className="w-6 h-6 text-primary" />
              ADVANCED SECURITY ANALYSIS
            </h1>
            <p className="text-sm text-gray-500 font-mono">
              Deep vulnerability validation, exploitation testing, and attack chain analysis
            </p>
          </div>
        </div>

        <div className="border-b border-gray-800 mb-6">
          <div className="flex gap-1 overflow-x-auto">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    'px-4 py-3 font-mono text-sm flex items-center gap-2 border-b-2 transition-colors whitespace-nowrap',
                    activeTab === tab.id
                      ? 'border-primary text-primary'
                      : 'border-transparent text-gray-500 hover:text-gray-300'
                  )}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="min-h-[400px]">
          {activeTab === 'validate' && <ValidationTab scanId={id!} />}
          {activeTab === 'exploit' && <ExploitTab scanId={id!} />}
          {activeTab === 'bypass' && <BypassTab scanId={id!} />}
          {activeTab === 'ai' && <AITab scanId={id!} />}
          {activeTab === 'chains' && <ChainsTab scanId={id!} />}
          {activeTab === 'profile' && <ProfileTab scanId={id!} />}
          {activeTab === 'api-test' && <APITestTab scanId={id!} />}
        </div>
      </div>
    </Layout>
  );
}


function ValidationTab({ scanId }: { scanId: string }) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any>(null);

  const runValidation = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/advanced/validate`, { method: 'POST' });
      const result = await res.json();
      setData(result);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold font-mono text-white">VALIDATION ENGINE</h2>
          <p className="text-xs text-gray-500">False positive detection via real HTTP requests • Error-based • Time-based • Boolean-based</p>
        </div>
        <button
          onClick={runValidation}
          disabled={loading}
          className="px-4 py-2 bg-primary text-black font-mono text-sm rounded hover:bg-primary/80 disabled:opacity-50 flex items-center gap-2"
        >
          <Play className="w-4 h-4" />
          {loading ? 'VALIDATING...' : 'RUN VALIDATION'}
        </button>
      </div>

      {data && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">TOTAL VALIDATED</p>
              <p className="text-2xl font-bold text-primary">{data.totalValidated}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">FALSE POSITIVES</p>
              <p className="text-2xl font-bold text-yellow-500">{data.falsePositivesFound}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">CONFIRMED</p>
              <p className="text-2xl font-bold text-red-500">{data.confirmedVulnerabilities}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">AVG SCORE</p>
              <p className="text-2xl font-bold text-primary">{data.avgValidationScore}%</p>
            </div>
          </div>

          {/* Detailed Validation Results */}
          {data.results && data.results.length > 0 && (
            <div className="space-y-3">
              <p className="text-xs text-gray-500 font-mono">DETAILED VALIDATION RESULTS ({data.results.length} findings tested)</p>
              {data.results.map((result: any, idx: number) => (
                <div key={idx} className={`bg-gray-900 rounded-lg p-4 border ${
                  result.isFalsePositive ? 'border-yellow-800' : 'border-red-800'
                }`}>
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <h4 className="font-mono text-white font-bold">{result.findingTitle}</h4>
                      <span className={`text-xs px-2 py-1 rounded font-mono ${
                        result.severity === 'critical' ? 'bg-red-900 text-red-200' :
                        result.severity === 'high' ? 'bg-orange-900 text-orange-200' :
                        result.severity === 'medium' ? 'bg-yellow-900 text-yellow-200' :
                        'bg-blue-900 text-blue-200'
                      }`}>
                        {result.severity.toUpperCase()}
                      </span>
                    </div>
                    <div className="text-right">
                      <div className={`text-sm font-mono font-bold ${
                        result.isFalsePositive ? "text-yellow-400" : "text-red-400"
                      }`}>
                        {result.isFalsePositive ? "⚠ FALSE POSITIVE" : "✓ CONFIRMED"}
                      </div>
                      <div className="text-xs text-gray-400 font-mono">Score: {result.validationScore}/100</div>
                    </div>
                  </div>

                  {/* Validation Method */}
                  <div className="mb-3 bg-black/30 rounded p-3 border border-gray-800">
                    <p className="text-xs text-gray-500 font-mono mb-1">VALIDATION METHOD</p>
                    <p className="text-xs text-gray-300 font-mono">{result.validationMethod}</p>
                  </div>

                  {/* Validation Details */}
                  <div className="mb-3 bg-black/30 rounded p-3 border border-gray-800">
                    <p className="text-xs text-gray-500 font-mono mb-1">VALIDATION DETAILS</p>
                    <p className="text-xs text-gray-300 font-mono">{result.validationDetails}</p>
                  </div>

                  {/* HTTP Status Comparison */}
                  <div className="grid grid-cols-2 gap-3 mb-3">
                    <div className="bg-black/30 rounded p-2 border border-gray-800">
                      <p className="text-xs text-gray-500 font-mono">Baseline Status</p>
                      <p className={`text-sm font-mono font-bold ${
                        result.baselineStatus >= 200 && result.baselineStatus < 300 ? 'text-green-400' :
                        result.baselineStatus >= 400 ? 'text-red-400' : 'text-yellow-400'
                      }`}>
                        HTTP {result.baselineStatus}
                      </p>
                    </div>
                    <div className="bg-black/30 rounded p-2 border border-gray-800">
                      <p className="text-xs text-gray-500 font-mono">Injected Status</p>
                      <p className={`text-sm font-mono font-bold ${
                        result.injectedStatus >= 200 && result.injectedStatus < 300 ? 'text-green-400' :
                        result.injectedStatus >= 400 ? 'text-red-400' : 'text-yellow-400'
                      }`}>
                        HTTP {result.injectedStatus}
                      </p>
                    </div>
                  </div>

                  {/* Response Difference */}
                  <div className="mb-3 bg-black/30 rounded p-3 border border-gray-800">
                    <p className="text-xs text-gray-500 font-mono mb-1">RESPONSE DIFFERENCE</p>
                    <p className="text-xs text-gray-300 font-mono">{result.responseDiff}</p>
                  </div>

                  {/* Detection Indicators */}
                  <div className="grid grid-cols-3 gap-2 mb-3">
                    <div className={`rounded p-2 border text-center ${
                      result.sqlErrorFound ? 'bg-red-950/20 border-red-800' : 'bg-gray-950 border-gray-800'
                    }`}>
                      <p className="text-xs text-gray-500 font-mono">SQL Error</p>
                      <p className={`text-sm font-mono font-bold ${result.sqlErrorFound ? 'text-red-400' : 'text-gray-600'}`}>
                        {result.sqlErrorFound ? '✓ YES' : '✗ NO'}
                      </p>
                    </div>
                    <div className={`rounded p-2 border text-center ${
                      result.timeDelayDetected ? 'bg-red-950/20 border-red-800' : 'bg-gray-950 border-gray-800'
                    }`}>
                      <p className="text-xs text-gray-500 font-mono">Time Delay</p>
                      <p className={`text-sm font-mono font-bold ${result.timeDelayDetected ? 'text-red-400' : 'text-gray-600'}`}>
                        {result.timeDelayDetected ? '✓ YES' : '✗ NO'}
                      </p>
                    </div>
                    <div className={`rounded p-2 border text-center ${
                      result.contentChangeDetected ? 'bg-red-950/20 border-red-800' : 'bg-gray-950 border-gray-800'
                    }`}>
                      <p className="text-xs text-gray-500 font-mono">Content Change</p>
                      <p className={`text-sm font-mono font-bold ${result.contentChangeDetected ? 'text-red-400' : 'text-gray-600'}`}>
                        {result.contentChangeDetected ? '✓ YES' : '✗ NO'}
                      </p>
                    </div>
                  </div>

                  {/* Payloads Tried */}
                  {result.payloadsTried && result.payloadsTried.length > 0 && (
                    <div className="bg-black/30 rounded p-3 border border-gray-800">
                      <p className="text-xs text-gray-500 font-mono mb-2">PAYLOADS TESTED ({result.payloadsTried.length})</p>
                      <div className="flex flex-wrap gap-2">
                        {result.payloadsTried.map((payload: string, pidx: number) => (
                          <span key={pidx} className="text-xs font-mono text-purple-400 bg-purple-950/20 border border-purple-800/30 px-2 py-1 rounded">
                            {payload.length > 40 ? payload.slice(0, 40) + '...' : payload}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {!data && !loading && (
        <div className="text-center py-16 text-gray-600">
          <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p className="font-mono text-sm">Run validation engine to detect false positives via real HTTP requests</p>
        </div>
      )}
    </div>
  );
}


function ExploitTab({ scanId }: { scanId: string }) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any>(null);

  const runExploit = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/advanced/exploit`, { method: 'POST' });
      const result = await res.json();
      setData(result);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold font-mono text-white">EXPLOITATION ENGINE</h2>
          <p className="text-xs text-gray-500">Safe payload execution • SQLi union-based • SSRF cloud metadata</p>
        </div>
        <button
          onClick={runExploit}
          disabled={loading}
          className="px-4 py-2 bg-red-900 border border-red-700 text-red-300 font-mono text-xs rounded hover:bg-red-800 disabled:opacity-50 flex items-center gap-2"
        >
          <Zap className="w-4 h-4" />
          {loading ? 'EXPLOITING...' : 'RUN EXPLOIT ENGINE'}
        </button>
      </div>

      {data && (
        <>
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">TOTAL TESTED</p>
              <p className="text-2xl font-bold text-primary">{data.totalExploited}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">EXPLOITS SUCCEEDED</p>
              <p className="text-2xl font-bold text-red-500">{data.exploitsSucceeded}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">FAILED</p>
              <p className="text-2xl font-bold text-green-500">{data.exploitsFailed}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">SUCCESS RATE</p>
              <p className="text-2xl font-bold text-orange-500">{data.successRate}%</p>
            </div>
          </div>

          <div className="space-y-2">
            {data.results?.map((r: any) => (
              <div key={r.id} className={`border rounded-lg p-4 ${r.exploitSuccess ? 'border-red-800 bg-red-950/10' : 'border-gray-800'}`}>
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <p className="text-sm font-mono text-white">{r.findingTitle}</p>
                    <p className="text-xs text-gray-500 font-mono">{r.exploitType}</p>
                  </div>
                  {r.exploitSuccess ? (
                    <span className="text-xs font-mono font-bold text-red-400 bg-red-950 border border-red-700 px-2 py-1 rounded">EXPLOITED ✓</span>
                  ) : (
                    <span className="text-xs font-mono font-bold text-green-400 bg-green-950 border border-green-800 px-2 py-1 rounded">FAILED ✗</span>
                  )}
                </div>
                <div className="text-xs text-gray-400 font-mono">
                  <p><span className="text-gray-500">Payload:</span> {r.payloadUsed}</p>
                  <p className="mt-1"><span className="text-gray-500">Impact:</span> {r.impactDemonstrated}</p>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {!data && !loading && (
        <div className="text-center py-16 text-gray-600">
          <Zap className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p className="font-mono text-sm">Run exploitation engine to test safe payloads</p>
        </div>
      )}
    </div>
  );
}


function BypassTab({ scanId }: { scanId: string }) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const runBypass = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/scans/${scanId}/advanced/bypass`, { method: 'POST' });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
      const result = await res.json();
      console.log('Bypass Engine data:', result);
      setData(result);
    } catch (err) {
      console.error('Bypass Engine error:', err);
      setError(err instanceof Error ? err.message : 'Failed to run bypass engine');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold font-mono text-white">WAF/CLOUDFLARE BYPASS ENGINE</h2>
          <p className="text-xs text-gray-500">Header injection • URL/double encoding • JSFuck • Real HTTP bypass testing</p>
        </div>
        <button
          onClick={runBypass}
          disabled={loading}
          className="px-4 py-2 bg-red-900 border border-red-700 text-red-300 font-mono text-xs rounded hover:bg-red-800 disabled:opacity-50 flex items-center gap-2"
        >
          <Shield className="w-4 h-4" />
          {loading ? 'BYPASSING...' : 'RUN BYPASS ENGINE'}
        </button>
      </div>

      {error && (
        <div className="bg-red-950 border border-red-800 rounded p-4 text-red-400 font-mono text-sm">
          Error: {error}
        </div>
      )}

      {data && (
        <>
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">WAF DETECTED</p>
              <p className="text-2xl font-bold text-red-500">{data.wafDetected ? 'YES' : 'NO'}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">CLOUDFLARE</p>
              <p className="text-2xl font-bold text-orange-500">{data.cloudflareDetected ? 'YES' : 'NO'}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">BYPASSES OK</p>
              <p className="text-2xl font-bold text-green-500">{data.bypassesSucceeded}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">BYPASS SCORE</p>
              <p className="text-2xl font-bold text-primary">{data.bypassScore}/100</p>
            </div>
          </div>

          {/* Bypass Summary */}
          {data.successfulBypass && (
            <div className={`border rounded p-4 ${data.bypassSuccess ? 'bg-green-950/10 border-green-800' : 'bg-red-950/10 border-red-800'}`}>
              <p className="text-xs text-gray-500 font-mono mb-1">BYPASS STATUS</p>
              <p className={`text-sm font-mono ${data.bypassSuccess ? 'text-green-400' : 'text-red-400'}`}>{data.successfulBypass}</p>
            </div>
          )}

          {/* Detailed Bypass Results per Finding */}
          {data.results && data.results.length > 0 && (
            <div className="space-y-4">
              <p className="text-xs text-gray-500 font-mono">DETAILED BYPASS ATTEMPTS ({data.results.length} findings tested)</p>
              {data.results.map((result: any, idx: number) => (
                <div key={idx} className="bg-gray-900 border border-gray-800 rounded p-4 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-mono text-white font-bold">{result.findingTitle}</h4>
                      <span className={`text-xs px-2 py-1 rounded font-mono ${
                        result.severity === 'critical' ? 'bg-red-900 text-red-200' :
                        result.severity === 'high' ? 'bg-orange-900 text-orange-200' :
                        result.severity === 'medium' ? 'bg-yellow-900 text-yellow-200' :
                        'bg-blue-900 text-blue-200'
                      }`}>
                        {result.severity.toUpperCase()}
                      </span>
                    </div>
                    <div className="text-right">
                      <div className={`text-sm font-mono font-bold ${result.bypassSuccess ? "text-green-400" : "text-red-400"}`}>
                        {result.bypassSuccess ? "✓ BYPASSED" : "✗ BLOCKED"}
                      </div>
                      <div className="text-xs text-gray-400 font-mono">Score: {result.bypassScore}/100</div>
                    </div>
                  </div>

                  {/* Individual Bypass Attempts */}
                  {result.attempts && result.attempts.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-xs text-gray-500 font-mono">BYPASS TECHNIQUES TESTED ({result.attempts.length})</p>
                      {result.attempts.map((attempt: any, aidx: number) => (
                        <div
                          key={aidx}
                          className={`p-3 rounded border ${
                            attempt.bypassSuccessful
                              ? "bg-green-950/20 border-green-800"
                              : attempt.blocked
                              ? "bg-red-950/20 border-red-800"
                              : "bg-gray-950 border-gray-700"
                          }`}
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <span className={`text-sm font-mono font-bold ${
                                  attempt.bypassSuccessful ? "text-green-400" :
                                  attempt.blocked ? "text-red-400" : "text-yellow-400"
                                }`}>
                                  {attempt.bypassSuccessful ? "✓" : attempt.blocked ? "✗" : "⚠"}
                                </span>
                                <span className="text-sm font-mono font-bold text-white">{attempt.technique}</span>
                              </div>
                              <p className="text-xs text-gray-400 ml-5">{attempt.explanation}</p>
                            </div>
                            <div className="text-right text-xs font-mono space-y-1">
                              <div className={`font-bold ${
                                attempt.status >= 200 && attempt.status < 300 ? "text-green-400" :
                                attempt.status >= 400 ? "text-red-400" : "text-yellow-400"
                              }`}>
                                HTTP {attempt.status}
                              </div>
                              <div className="text-gray-500">{attempt.responseTime}ms</div>
                              <div className="text-gray-500">{attempt.responseSize}B</div>
                            </div>
                          </div>

                          {/* Payload & Headers */}
                          <div className="space-y-1 text-xs font-mono">
                            <div>
                              <span className="text-gray-500">Payload:</span>
                              <code className="ml-2 text-purple-400 bg-black px-2 py-0.5 rounded">
                                {attempt.payload.length > 80 ? attempt.payload.slice(0, 80) + "..." : attempt.payload}
                              </code>
                            </div>
                            
                            {Object.keys(attempt.headers).length > 0 && (
                              <div>
                                <span className="text-gray-500">Headers:</span>
                                <code className="ml-2 text-blue-400 bg-black px-2 py-0.5 rounded text-xs">
                                  {Object.entries(attempt.headers).slice(0, 2).map(([k, v]) => `${k}: ${v}`).join(", ")}
                                  {Object.keys(attempt.headers).length > 2 && ` +${Object.keys(attempt.headers).length - 2} more`}
                                </code>
                              </div>
                            )}

                            {attempt.wafSignature !== "None" && (
                              <div>
                                <span className="text-gray-500">WAF:</span>
                                <span className="ml-2 text-orange-400">{attempt.wafSignature}</span>
                              </div>
                            )}

                            {attempt.responseExcerpt && (
                              <div>
                                <span className="text-gray-500">Response:</span>
                                <code className="ml-2 text-gray-400 bg-black px-2 py-0.5 rounded text-xs">
                                  {attempt.responseExcerpt.slice(0, 100)}...
                                </code>
                              </div>
                            )}

                            {/* Curl Command */}
                            <details className="mt-2">
                              <summary className="text-xs text-blue-400 cursor-pointer hover:text-blue-300 font-mono">
                                ▸ Show curl command
                              </summary>
                              <code className="block mt-1 text-xs text-gray-300 bg-black p-2 rounded overflow-x-auto">
                                {attempt.curlCommand}
                              </code>
                            </details>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Result Summary */}
                  <div className="pt-3 border-t border-gray-700 text-xs text-gray-400 font-mono">
                    {result.bypassDetails}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Headers Manipulated */}
          {Object.keys(data.headersManipulated || {}).length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-2">HEADERS MANIPULATED FOR BYPASS</p>
              <div className="space-y-1 text-xs font-mono">
                {Object.entries(data.headersManipulated).map(([key, value]) => (
                  <div key={key} className="text-gray-300">
                    <span className="text-blue-400">{key}:</span> <span className="text-purple-400">{value as string}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* All Techniques Summary */}
          {data.allBypassTechniques?.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-2">ALL TECHNIQUES TESTED</p>
              <div className="flex flex-wrap gap-2">
                {data.allBypassTechniques.map((t: string, i: number) => {
                  const isPassed = t.includes("PASSED") || (!t.includes("BLOCKED") && !t.includes("403") && !t.includes("406"));
                  return (
                    <span key={i} className={`text-xs font-mono px-2 py-1 rounded ${
                      isPassed ? 'bg-green-950 border border-green-800 text-green-300' : 'bg-red-950 border border-red-800 text-red-300'
                    }`}>
                      {t}
                    </span>
                  );
                })}
              </div>
            </div>
          )}
        </>
      )}

      {!data && !loading && (
        <div className="text-center py-16 text-gray-600">
          <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p className="font-mono text-sm">Run bypass engine to test WAF & Cloudflare bypass techniques</p>
        </div>
      )}
    </div>
  );
}


function AITab({ scanId }: { scanId: string }) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchAI = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/scans/${scanId}/advanced/ai-attack-plan`);
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        const result = await res.json();
        console.log('AI Attack Plan data:', result);
        setData(result);
      } catch (err) {
        console.error('AI Attack Plan error:', err);
        setError(err instanceof Error ? err.message : 'Failed to load AI attack plan');
      } finally {
        setLoading(false);
      }
    };
    fetchAI();
  }, [scanId]);

  if (loading) return <div className="text-center py-16 text-primary font-mono">Loading AI Attack Plan...</div>;
  if (error) return <div className="text-center py-16 text-red-500 font-mono">Error: {error}</div>;
  if (!data) return <div className="text-center py-16 text-gray-500 font-mono">No data available</div>;

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-bold font-mono text-white">AI ATTACK DECISION ENGINE</h2>
        <p className="text-xs text-gray-500">Attack prioritization • WAF detection • Adaptive strategies</p>
      </div>

      {data && (
        <>
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">WAF DETECTED</p>
              <p className="text-2xl font-bold text-red-500">{data.wafDetected ? 'YES' : 'NO'}</p>
              {data.wafVendor && <p className="text-xs text-gray-400 mt-1">{data.wafVendor}</p>}
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">BYPASS MODE</p>
              <p className="text-2xl font-bold text-orange-500">{data.bypassMode ? 'ACTIVE' : 'OFF'}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">AI SCORE</p>
              <p className="text-2xl font-bold text-primary">{data.totalScore}</p>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded p-4">
            <p className="text-xs text-gray-500 font-mono mb-2">ATTACK STRATEGY</p>
            <p className="text-sm text-white font-mono">{data.attackStrategy}</p>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded p-4">
            <p className="text-xs text-gray-500 font-mono mb-2">PRIMARY OBJECTIVE</p>
            <p className="text-sm text-red-400 font-mono">{data.primaryObjective}</p>
          </div>

          {data.attackOrder?.length > 0 && (
            <div>
              <p className="text-sm font-mono text-white mb-2">ATTACK ORDER (AI Prioritized)</p>
              <div className="space-y-2">
                {data.attackOrder.slice(0, 10).map((attack: any) => (
                  <div key={attack.findingId} className="bg-gray-900 border border-gray-800 rounded p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono text-primary">P{attack.priority}</span>
                      <span className="text-xs font-mono text-gray-400">{attack.vulnType.toUpperCase()}</span>
                    </div>
                    <p className="text-xs text-white font-mono mb-1">{attack.reason}</p>
                    <p className="text-xs text-gray-500 font-mono">{attack.action}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}


function ChainsTab({ scanId }: { scanId: string }) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchChains = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/scans/${scanId}/advanced/chains`);
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        const result = await res.json();
        console.log('Vulnerability Chains data:', result);
        setData(result);
      } catch (err) {
        console.error('Vulnerability Chains error:', err);
        setError(err instanceof Error ? err.message : 'Failed to load vulnerability chains');
      } finally {
        setLoading(false);
      }
    };
    fetchChains();
  }, [scanId]);

  if (loading) return <div className="text-center py-16 text-primary font-mono">Loading Vulnerability Chains...</div>;
  if (error) return <div className="text-center py-16 text-red-500 font-mono">Error: {error}</div>;

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-bold font-mono text-white">VULNERABILITY CHAINING ENGINE</h2>
        <p className="text-xs text-gray-500">Multi-step attack paths • Exploit chains • Maximum impact analysis</p>
      </div>

      {data?.chains?.length > 0 ? (
        <div className="space-y-4">
          {data.chains.map((chain: any, idx: number) => (
            <div key={idx} className="bg-gray-900 border border-red-800 rounded p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-mono text-red-400 font-bold">{chain.chainName}</h3>
                <span className="text-xs font-mono text-gray-400 uppercase">{chain.severity}</span>
              </div>
              
              <div className="space-y-2 mb-3">
                {chain.steps?.map((step: any) => (
                  <div key={step.step} className="flex gap-3">
                    <span className="text-xs font-mono text-primary shrink-0">STEP {step.step}</span>
                    <div className="flex-1">
                      <p className="text-xs text-white font-mono">{step.action}</p>
                      <p className="text-xs text-gray-500 font-mono">{step.result}</p>
                    </div>
                  </div>
                ))}
              </div>

              <div className="border-t border-gray-800 pt-3 space-y-2">
                <div>
                  <p className="text-xs text-gray-500 font-mono">FINAL IMPACT</p>
                  <p className="text-xs text-red-400 font-mono">{chain.finalImpact}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 font-mono">BUSINESS RISK</p>
                  <p className="text-xs text-orange-400 font-mono">{chain.businessRisk}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 font-mono">CONFIDENCE</p>
                  <p className="text-xs text-primary font-mono">{chain.confidenceScore}%</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-16 text-gray-600">
          <Link2 className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p className="font-mono text-sm">No vulnerability chains detected</p>
        </div>
      )}
    </div>
  );
}


function ProfileTab({ scanId }: { scanId: string }) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchProfile = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/scans/${scanId}/advanced/profile`);
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        const result = await res.json();
        console.log('Target Profile data:', result);
        setData(result);
      } catch (err) {
        console.error('Target Profile error:', err);
        setError(err instanceof Error ? err.message : 'Failed to load target profile');
      } finally {
        setLoading(false);
      }
    };
    fetchProfile();
  }, [scanId]);

  if (loading) return <div className="text-center py-16 text-primary font-mono">Loading Target Profile...</div>;
  if (error) return <div className="text-center py-16 text-red-500 font-mono">Error: {error}</div>;
  if (!data) return <div className="text-center py-16 text-gray-500 font-mono">No data available</div>;

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-bold font-mono text-white">TARGET PROFILING ENGINE</h2>
        <p className="text-xs text-gray-500">Real HTTP fingerprinting • 50+ frameworks • Tech stack detection • Attack surface mapping</p>
      </div>

      {data && (
        <>
          {/* Target URL */}
          <div className="bg-gray-900 border border-gray-800 rounded p-4">
            <p className="text-xs text-gray-500 font-mono mb-1">TARGET URL</p>
            <p className="text-sm text-primary font-mono break-all">{data.targetUrl}</p>
          </div>

          {/* Framework & Language Detection */}
          <div className="bg-gray-900 border border-red-900/30 rounded p-4">
            <p className="text-xs text-gray-500 font-mono mb-3">🔍 FRAMEWORK & LANGUAGE DETECTION (Real HTTP Fingerprinting)</p>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-black/30 rounded p-3 border border-gray-800">
                <p className="text-xs text-gray-500 font-mono mb-1">FRAMEWORK</p>
                <p className={`text-lg font-mono font-bold ${data.framework !== 'Unknown' ? 'text-green-400' : 'text-red-400'}`}>
                  {data.framework}
                </p>
                {data.framework !== 'Unknown' && (
                  <p className="text-xs text-gray-400 font-mono mt-1">✓ Detected via real HTTP response</p>
                )}
              </div>
              <div className="bg-black/30 rounded p-3 border border-gray-800">
                <p className="text-xs text-gray-500 font-mono mb-1">LANGUAGE</p>
                <p className={`text-lg font-mono font-bold ${data.language !== 'Unknown' ? 'text-green-400' : 'text-red-400'}`}>
                  {data.language}
                </p>
                {data.language !== 'Unknown' && (
                  <p className="text-xs text-gray-400 font-mono mt-1">✓ Detected via headers & body analysis</p>
                )}
              </div>
            </div>
          </div>

          {/* Server & Infrastructure */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">SERVER</p>
              <p className="text-sm text-white font-mono">{data.serverType}</p>
              {data.serverVersion && data.serverVersion !== 'Fingerprint via error pages and headers' && (
                <p className="text-xs text-gray-400 font-mono mt-1">{data.serverVersion}</p>
              )}
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">CLOUD PROVIDER</p>
              <p className="text-sm text-white font-mono">{data.cloudProvider}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">CDN</p>
              <p className="text-sm text-white font-mono">{data.cdnProvider}</p>
            </div>
          </div>

          {/* CMS & API Type */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">CMS</p>
              <p className="text-sm text-white font-mono">{data.cms}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">API TYPE</p>
              <p className="text-sm text-white font-mono">{data.apiType}</p>
            </div>
          </div>

          {/* WAF Detection */}
          <div className="bg-gray-900 border border-orange-900/30 rounded p-4">
            <p className="text-xs text-gray-500 font-mono mb-3">🛡️ WAF DETECTION</p>
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-black/30 rounded p-3 border border-gray-800">
                <p className="text-xs text-gray-500 font-mono mb-1">TYPE</p>
                <p className="text-sm text-white font-mono">{data.wafType}</p>
              </div>
              <div className="bg-black/30 rounded p-3 border border-gray-800">
                <p className="text-xs text-gray-500 font-mono mb-1">VENDOR</p>
                <p className={`text-sm font-mono font-bold ${data.wafVendor !== 'None' ? 'text-red-400' : 'text-green-400'}`}>
                  {data.wafVendor}
                </p>
              </div>
              <div className="bg-black/30 rounded p-3 border border-gray-800">
                <p className="text-xs text-gray-500 font-mono mb-1">CONFIDENCE</p>
                <p className="text-sm text-primary font-mono font-bold">{data.wafConfidence}%</p>
              </div>
            </div>
          </div>

          {/* Fingerprints */}
          {data.fingerprints && Object.keys(data.fingerprints).length > 0 && (
            <div className="bg-gray-900 border border-blue-900/30 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-3">🔐 TECHNOLOGY FINGERPRINTS</p>
              <div className="grid grid-cols-2 gap-3">
                {Object.entries(data.fingerprints).map(([key, value]) => (
                  <div key={key} className="bg-black/30 rounded p-2 border border-gray-800">
                    <p className="text-xs text-gray-500 font-mono">{key}</p>
                    <p className="text-sm text-blue-400 font-mono">{value as string}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Real Headers Captured */}
          {data.headers && Object.keys(data.headers).length > 0 && (
            <div className="bg-gray-900 border border-purple-900/30 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-3">📡 HTTP HEADERS (Real Response)</p>
              <div className="space-y-1 max-h-64 overflow-y-auto">
                {Object.entries(data.headers).map(([key, value]) => (
                  <div key={key} className="text-xs font-mono">
                    <span className="text-purple-400">{key}:</span>{' '}
                    <span className="text-gray-300">{value as string}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Cookies */}
          {data.cookies && data.cookies.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-2">🍪 COOKIES DETECTED</p>
              <div className="flex flex-wrap gap-2">
                {data.cookies.map((cookie: string, i: number) => (
                  <span key={i} className="text-xs font-mono text-yellow-400 bg-yellow-950/20 border border-yellow-800/30 px-2 py-1 rounded">
                    {cookie}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Attack Surface */}
          {data.attackSurface?.length > 0 && (
            <div className="bg-gray-900 border border-red-900/30 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-3">⚔️ ATTACK SURFACE ANALYSIS</p>
              <div className="space-y-2">
                {data.attackSurface.map((surface: string, i: number) => (
                  <div key={i} className="flex items-start gap-2 bg-red-950/10 border border-red-900/30 rounded p-2">
                    <span className="text-red-400 text-xs">●</span>
                    <p className="text-xs text-red-300 font-mono flex-1">{surface}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detected Services */}
          {data.detectedServices?.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-2">🔧 DETECTED SERVICES</p>
              <div className="flex flex-wrap gap-2">
                {data.detectedServices.map((service: string, i: number) => (
                  <span key={i} className="text-xs font-mono text-primary bg-primary/10 border border-primary/30 px-3 py-1 rounded">
                    {service}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Additional Info */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">AUTH MECHANISM</p>
              <p className="text-sm text-white font-mono">{data.authMechanism}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">TLS VERSION</p>
              <p className="text-sm text-white font-mono">{data.tlsVersion}</p>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
