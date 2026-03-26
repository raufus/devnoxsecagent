import { useState } from 'react';
import { Play, CheckCircle, XCircle, AlertTriangle, Loader, Shield } from 'lucide-react';

interface TestResult {
  endpoint: string;
  method: string;
  status: 'passed' | 'vulnerable' | 'failed';
  statusCode: number;
  responseTime: number;
  vulnerabilities: string[];
  details: string;
  tests: {
    sqlInjection: { tested: boolean; vulnerable: boolean; payload?: string };
    xss: { tested: boolean; vulnerable: boolean; payload?: string };
    authBypass: { tested: boolean; vulnerable: boolean };
    rateLimiting: { tested: boolean; vulnerable: boolean };
    idor: { tested: boolean; vulnerable: boolean };
  };
}

export function APITestTab({ scanId }: { scanId: string }) {
  const [testing, setTesting] = useState(false);
  const [data, setData] = useState<any>(null);

  const runTests = async () => {
    setTesting(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/advanced/api-test`, { method: 'POST' });
      const result = await res.json();
      setData(result);
    } catch (err) {
      console.error(err);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold font-mono text-white">API SECURITY TESTING</h2>
          <p className="text-xs text-gray-500">Automatic endpoint testing • SQLi • XSS • Auth bypass • Rate limiting • IDOR</p>
        </div>
        <button
          onClick={runTests}
          disabled={testing}
          className="px-4 py-2 bg-red-900 border border-red-700 text-red-300 font-mono text-xs rounded hover:bg-red-800 disabled:opacity-50 flex items-center gap-2"
        >
          {testing ? <Loader className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {testing ? 'TESTING APIs...' : 'RUN API TESTS'}
        </button>
      </div>

      {data && (
        <>
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">TOTAL TESTED</p>
              <p className="text-2xl font-bold text-primary">{data.totalTested}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">PASSED</p>
              <p className="text-2xl font-bold text-green-500">{data.passed}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">VULNERABLE</p>
              <p className="text-2xl font-bold text-red-500">{data.vulnerable}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded p-4">
              <p className="text-xs text-gray-500 font-mono mb-1">FAILED</p>
              <p className="text-2xl font-bold text-yellow-500">{data.failed}</p>
            </div>
          </div>

          <p className="text-xs text-gray-500 font-mono">DETAILED RESULTS</p>
          {data.results?.map((result: TestResult, idx: number) => (
            <div
              key={idx}
              className={`bg-gray-900 rounded p-4 border ${
                result.status === 'vulnerable' ? 'border-red-800' :
                result.status === 'passed' ? 'border-green-800' :
                'border-yellow-800'
              }`}
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-xs px-2 py-1 rounded font-mono font-bold ${
                      result.method === 'GET' ? 'bg-blue-900 text-blue-200' :
                      result.method === 'POST' ? 'bg-green-900 text-green-200' :
                      result.method === 'PUT' ? 'bg-yellow-900 text-yellow-200' :
                      result.method === 'DELETE' ? 'bg-red-900 text-red-200' :
                      'bg-gray-800 text-gray-300'
                    }`}>
                      {result.method}
                    </span>
                    <span className="text-sm text-white font-mono break-all">{result.endpoint}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {result.status === 'vulnerable' && <XCircle className="w-5 h-5 text-red-400" />}
                  {result.status === 'passed' && <CheckCircle className="w-5 h-5 text-green-400" />}
                  {result.status === 'failed' && <AlertTriangle className="w-5 h-5 text-yellow-400" />}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 mb-3">
                <div className="bg-black/30 rounded p-2">
                  <p className="text-xs text-gray-500 font-mono">Status Code</p>
                  <p className={`text-sm font-mono font-bold ${
                    result.statusCode >= 200 && result.statusCode < 300 ? 'text-green-400' :
                    result.statusCode >= 400 ? 'text-red-400' : 'text-yellow-400'
                  }`}>
                    {result.statusCode}
                  </p>
                </div>
                <div className="bg-black/30 rounded p-2">
                  <p className="text-xs text-gray-500 font-mono">Response Time</p>
                  <p className="text-sm font-mono text-white">{result.responseTime}ms</p>
                </div>
              </div>

              {/* Security Tests */}
              <div className="space-y-2 mb-3">
                <p className="text-xs text-gray-500 font-mono">SECURITY TESTS</p>
                <div className="grid grid-cols-2 gap-2">
                  {/* SQL Injection */}
                  <div className={`rounded p-2 border ${
                    result.tests.sqlInjection.vulnerable ? 'bg-red-950/20 border-red-800' : 
                    result.tests.sqlInjection.tested ? 'bg-green-950/20 border-green-800' : 
                    'bg-gray-950 border-gray-800'
                  }`}>
                    <p className="text-xs text-gray-500 font-mono">SQL Injection</p>
                    <p className={`text-sm font-mono font-bold ${
                      result.tests.sqlInjection.vulnerable ? 'text-red-400' : 
                      result.tests.sqlInjection.tested ? 'text-green-400' : 'text-gray-600'
                    }`}>
                      {result.tests.sqlInjection.vulnerable ? '✗ VULNERABLE' : 
                       result.tests.sqlInjection.tested ? '✓ SECURE' : '- NOT TESTED'}
                    </p>
                    {result.tests.sqlInjection.payload && (
                      <p className="text-xs text-purple-400 font-mono mt-1 truncate">{result.tests.sqlInjection.payload}</p>
                    )}
                  </div>

                  {/* XSS */}
                  <div className={`rounded p-2 border ${
                    result.tests.xss.vulnerable ? 'bg-red-950/20 border-red-800' : 
                    result.tests.xss.tested ? 'bg-green-950/20 border-green-800' : 
                    'bg-gray-950 border-gray-800'
                  }`}>
                    <p className="text-xs text-gray-500 font-mono">XSS (Reflected)</p>
                    <p className={`text-sm font-mono font-bold ${
                      result.tests.xss.vulnerable ? 'text-red-400' : 
                      result.tests.xss.tested ? 'text-green-400' : 'text-gray-600'
                    }`}>
                      {result.tests.xss.vulnerable ? '✗ VULNERABLE' : 
                       result.tests.xss.tested ? '✓ SECURE' : '- NOT TESTED'}
                    </p>
                    {result.tests.xss.payload && (
                      <p className="text-xs text-purple-400 font-mono mt-1 truncate">{result.tests.xss.payload}</p>
                    )}
                  </div>

                  {/* Auth Bypass */}
                  <div className={`rounded p-2 border ${
                    result.tests.authBypass.vulnerable ? 'bg-red-950/20 border-red-800' : 
                    result.tests.authBypass.tested ? 'bg-green-950/20 border-green-800' : 
                    'bg-gray-950 border-gray-800'
                  }`}>
                    <p className="text-xs text-gray-500 font-mono">Auth Bypass</p>
                    <p className={`text-sm font-mono font-bold ${
                      result.tests.authBypass.vulnerable ? 'text-red-400' : 
                      result.tests.authBypass.tested ? 'text-green-400' : 'text-gray-600'
                    }`}>
                      {result.tests.authBypass.vulnerable ? '✗ VULNERABLE' : 
                       result.tests.authBypass.tested ? '✓ SECURE' : '- NOT TESTED'}
                    </p>
                  </div>

                  {/* Rate Limiting */}
                  <div className={`rounded p-2 border ${
                    result.tests.rateLimiting.vulnerable ? 'bg-red-950/20 border-red-800' : 
                    result.tests.rateLimiting.tested ? 'bg-green-950/20 border-green-800' : 
                    'bg-gray-950 border-gray-800'
                  }`}>
                    <p className="text-xs text-gray-500 font-mono">Rate Limiting</p>
                    <p className={`text-sm font-mono font-bold ${
                      result.tests.rateLimiting.vulnerable ? 'text-red-400' : 
                      result.tests.rateLimiting.tested ? 'text-green-400' : 'text-gray-600'
                    }`}>
                      {result.tests.rateLimiting.vulnerable ? '✗ MISSING' : 
                       result.tests.rateLimiting.tested ? '✓ PRESENT' : '- NOT TESTED'}
                    </p>
                  </div>

                  {/* IDOR */}
                  <div className={`rounded p-2 border ${
                    result.tests.idor.vulnerable ? 'bg-red-950/20 border-red-800' : 
                    result.tests.idor.tested ? 'bg-green-950/20 border-green-800' : 
                    'bg-gray-950 border-gray-800'
                  }`}>
                    <p className="text-xs text-gray-500 font-mono">IDOR</p>
                    <p className={`text-sm font-mono font-bold ${
                      result.tests.idor.vulnerable ? 'text-red-400' : 
                      result.tests.idor.tested ? 'text-green-400' : 'text-gray-600'
                    }`}>
                      {result.tests.idor.vulnerable ? '✗ VULNERABLE' : 
                       result.tests.idor.tested ? '✓ SECURE' : '- NOT TESTED'}
                    </p>
                  </div>
                </div>
              </div>

              {result.vulnerabilities.length > 0 && (
                <div className="bg-red-950/20 border border-red-800 rounded p-3 mb-2">
                  <p className="text-xs text-gray-500 font-mono mb-2">VULNERABILITIES FOUND</p>
                  <div className="flex flex-wrap gap-2">
                    {result.vulnerabilities.map((vuln, vidx) => (
                      <span key={vidx} className="text-xs font-mono text-red-300 bg-red-950 border border-red-800 px-2 py-1 rounded">
                        {vuln}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <p className="text-xs text-gray-400 font-mono">{result.details}</p>
            </div>
          ))}
        </>
      )}

      {!data && !testing && (
        <div className="text-center py-16 text-gray-600">
          <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p className="font-mono text-sm">Run API security tests to automatically test all discovered endpoints</p>
          <p className="font-mono text-xs text-gray-700 mt-2">Tests: SQL Injection, XSS, Auth Bypass, Rate Limiting, IDOR</p>
        </div>
      )}
    </div>
  );
}
