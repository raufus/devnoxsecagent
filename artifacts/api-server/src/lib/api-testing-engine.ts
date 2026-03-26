import { httpRequest } from './real-http.js';

interface APIEndpoint {
  url: string;
  method: string;
  params?: Record<string, string>;
}

interface APITestResult {
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

export async function runAPITestingEngine(
  targetUrl: string,
  endpoints: string[]
): Promise<{
  totalTested: number;
  passed: number;
  vulnerable: number;
  failed: number;
  results: APITestResult[];
}> {
  const results: APITestResult[] = [];
  let passed = 0;
  let vulnerable = 0;
  let failed = 0;

  // Extract unique endpoints from scan
  const uniqueEndpoints = extractEndpoints(targetUrl, endpoints);

  for (const endpoint of uniqueEndpoints.slice(0, 20)) {
    const result = await testEndpoint(endpoint);
    results.push(result);

    if (result.status === 'passed') passed++;
    else if (result.status === 'vulnerable') vulnerable++;
    else failed++;
  }

  return {
    totalTested: results.length,
    passed,
    vulnerable,
    failed,
    results,
  };
}

function extractEndpoints(targetUrl: string, endpoints: string[]): APIEndpoint[] {
  const apiEndpoints: APIEndpoint[] = [];
  const baseUrl = new URL(targetUrl);

  // Add base URL
  apiEndpoints.push({ url: targetUrl, method: 'GET' });

  // Add discovered endpoints
  for (const endpoint of endpoints) {
    try {
      let fullUrl = endpoint;
      if (!endpoint.startsWith('http')) {
        fullUrl = `${baseUrl.protocol}//${baseUrl.host}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`;
      }

      // Add GET and POST variants
      apiEndpoints.push({ url: fullUrl, method: 'GET' });
      if (endpoint.includes('api') || endpoint.includes('login') || endpoint.includes('register')) {
        apiEndpoints.push({ url: fullUrl, method: 'POST' });
      }
    } catch (e) {
      // Skip invalid URLs
    }
  }

  // Remove duplicates
  const seen = new Set<string>();
  return apiEndpoints.filter(ep => {
    const key = `${ep.method}:${ep.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function testEndpoint(endpoint: APIEndpoint): Promise<APITestResult> {
  const result: APITestResult = {
    endpoint: endpoint.url,
    method: endpoint.method,
    status: 'passed',
    statusCode: 0,
    responseTime: 0,
    vulnerabilities: [],
    details: '',
    tests: {
      sqlInjection: { tested: false, vulnerable: false },
      xss: { tested: false, vulnerable: false },
      authBypass: { tested: false, vulnerable: false },
      rateLimiting: { tested: false, vulnerable: false },
      idor: { tested: false, vulnerable: false },
    },
  };

  try {
    const startTime = Date.now();

    // Test 1: Baseline request
    const baselineResponse = await httpRequest(endpoint.url, {
      method: endpoint.method,
      headers: { 'User-Agent': 'DevNox-SecAgent/1.0' },
      timeout: 5000,
    });
    result.statusCode = baselineResponse.status;
    result.responseTime = Date.now() - startTime;

    // Test 2: SQL Injection
    result.tests.sqlInjection.tested = true;
    const sqlPayloads = [
      "' OR '1'='1",
      "1' UNION SELECT NULL--",
      "'; DROP TABLE users--",
      "1' AND SLEEP(5)--",
    ];

    for (const payload of sqlPayloads) {
      try {
        const testUrl = endpoint.url.includes('?')
          ? `${endpoint.url}&test=${encodeURIComponent(payload)}`
          : `${endpoint.url}?test=${encodeURIComponent(payload)}`;

        const sqlResponse = await httpRequest(testUrl, {
          method: endpoint.method,
          timeout: 6000,
        });

        const body = sqlResponse.body.toLowerCase();
        if (
          body.includes('sql') ||
          body.includes('syntax') ||
          body.includes('mysql') ||
          body.includes('postgresql') ||
          body.includes('ora-') ||
          sqlResponse.responseTime > 5000
        ) {
          result.tests.sqlInjection.vulnerable = true;
          result.tests.sqlInjection.payload = payload;
          result.vulnerabilities.push('SQL Injection');
          break;
        }
      } catch (e) {
        // Continue testing
      }
    }

    // Test 3: XSS (Reflected)
    result.tests.xss.tested = true;
    const xssPayloads = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '"><script>alert(document.domain)</script>',
      "javascript:alert('XSS')",
    ];

    for (const payload of xssPayloads) {
      try {
        const testUrl = endpoint.url.includes('?')
          ? `${endpoint.url}&xss=${encodeURIComponent(payload)}`
          : `${endpoint.url}?xss=${encodeURIComponent(payload)}`;

        const xssResponse = await httpRequest(testUrl, {
          method: endpoint.method,
          timeout: 5000,
        });

        if (xssResponse.body.includes(payload) || xssResponse.body.includes('alert(')) {
          result.tests.xss.vulnerable = true;
          result.tests.xss.payload = payload;
          result.vulnerabilities.push('XSS (Reflected)');
          break;
        }
      } catch (e) {
        // Continue testing
      }
    }

    // Test 4: Authentication Bypass
    result.tests.authBypass.tested = true;
    try {
      const noAuthResponse = await httpRequest(endpoint.url, {
        method: endpoint.method,
        headers: {}, // No auth headers
        timeout: 5000,
      });

      // If we get 200 on sensitive endpoints without auth
      if (
        noAuthResponse.status === 200 &&
        (endpoint.url.includes('admin') ||
          endpoint.url.includes('dashboard') ||
          endpoint.url.includes('profile') ||
          endpoint.url.includes('api'))
      ) {
        result.tests.authBypass.vulnerable = true;
        result.vulnerabilities.push('Missing Authentication');
      }
    } catch (e) {
      // Auth might be working
    }

    // Test 5: Rate Limiting
    result.tests.rateLimiting.tested = true;
    try {
      const rapidRequests = await Promise.all(
        Array(15)
          .fill(null)
          .map(() =>
            httpRequest(endpoint.url, {
              method: endpoint.method,
              timeout: 3000,
            }).catch(() => ({ status: 0 }))
          )
      );

      const rateLimited = rapidRequests.some((r: any) => r.status === 429);
      if (!rateLimited && rapidRequests.filter((r: any) => r.status === 200).length > 10) {
        result.tests.rateLimiting.vulnerable = true;
        result.vulnerabilities.push('No Rate Limiting');
      }
    } catch (e) {
      // Rate limiting might be working
    }

    // Test 6: IDOR (Insecure Direct Object Reference)
    result.tests.idor.tested = true;
    if (endpoint.url.match(/\/\d+/) || endpoint.url.includes('id=')) {
      try {
        // Try accessing different IDs
        const testUrl = endpoint.url.replace(/\/\d+/, '/99999').replace(/id=\d+/, 'id=99999');
        const idorResponse = await httpRequest(testUrl, {
          method: endpoint.method,
          timeout: 5000,
        });

        if (idorResponse.status === 200 && idorResponse.body.length > 100) {
          result.tests.idor.vulnerable = true;
          result.vulnerabilities.push('IDOR (Insecure Direct Object Reference)');
        }
      } catch (e) {
        // IDOR protection might be working
      }
    }

    // Determine final status
    if (result.vulnerabilities.length > 0) {
      result.status = 'vulnerable';
      result.details = `Found ${result.vulnerabilities.length} vulnerabilities: ${result.vulnerabilities.join(', ')}`;
    } else if (result.statusCode >= 200 && result.statusCode < 300) {
      result.status = 'passed';
      result.details = 'All security tests passed';
    } else {
      result.status = 'failed';
      result.details = `HTTP ${result.statusCode} - Endpoint may be unavailable`;
    }
  } catch (error) {
    result.status = 'failed';
    result.details = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
  }

  return result;
}
