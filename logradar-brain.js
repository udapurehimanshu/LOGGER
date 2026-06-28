// ═══════════════════════════════════════════════════════════════════════════
//  LogRadar Intelligence Brain v1.0
//  Based on: LogRadar-Intelligence/SYSTEM_PROMPT.md + knowledge engines
//  Role: Senior L3 Support Engineer — Systematic Investigation Methodology
//  Integrates: Investigation Engine · API Engine · Confidence Engine · Playbooks
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

// ─── Pattern Library (from api_engine.md + investigation_engine.md) ──────────
const BRAIN_PATTERNS = {
  BLANK_API: {
    id: 'BLANK_API',
    name: 'Blank API Response',
    description: 'HTTP 200 returned but response body contains zero records. This is NOT an API failure — it is a business failure.',
    icon: '📭',
    severity: 'MEDIUM',
    color: '#F59E0B',
    detect: (api) => {
      if (!api || api.status !== 200) return false;
      const r = api.response || '';
      return r.trim() === '[]' || r.trim() === '{}' ||
        /\"count\"\s*:\s*0\b/i.test(r) ||
        /\"records\"\s*:\s*0\b/i.test(r) ||
        /\"items\"\s*:\s*\[\s*\]/i.test(r) ||
        /\"data\"\s*:\s*\[\s*\]/i.test(r) ||
        /totalResults\s*[=:]\s*0/i.test(r) ||
        /\"total\"\s*:\s*0/i.test(r);
    },
    investigation: (api) => ({
      rootCause: 'Blank API Response (HTTP 200 + Zero Records)',
      pattern: 'BLANK_API',
      evidence: [
        `HTTP Status: ${api.status} (API call technically succeeded)`,
        `Response body contains zero records`,
        `This is a business failure, not an API failure`,
      ],
      possibleCauses: [
        'Query filter parameters are too restrictive',
        'Data does not exist in the system for the given criteria',
        'User may lack data-level permission (Oracle returned 200 but filtered records)',
        'Data was recently purged or is inactive',
      ],
      recommendations: [
        { action: 'Add logger.trace() to log exact query parameters sent', priority: 'HIGH', why: 'Identify what filter criteria was used' },
        { action: 'Verify data exists in the backend system matching the criteria', priority: 'HIGH', why: 'Confirm whether it is a data issue or filter issue' },
        { action: 'Check if user has data-level access to the records being queried', priority: 'MEDIUM', why: 'Oracle may silently filter out records the user cannot see' },
        { action: 'Add code: if (items.length === 0) { setStatusMessage("No Data", "No records found") }', priority: 'HIGH', why: 'Provide user feedback instead of silent failure' },
      ],
      loggerSuggestion: 'logger.trace("Query parameters sent: " + JSON.stringify(payload));\nlogger.warn("Blank API: " + apiName + " returned 0 records for criteria: " + JSON.stringify(filters));',
      confidence: 90,
      nextSteps: 'Ask user: What data were you searching for? Then check if that data exists in Oracle.',
    }),
  },

  AUTH_FAILURE_403: {
    id: 'AUTH_FAILURE_403',
    name: 'Authorization Failure (HTTP 403)',
    description: 'Authenticated user does not have permission to access this resource. Missing duty role, job role, or data role.',
    icon: '🔒',
    severity: 'HIGH',
    color: '#DC2626',
    detect: (api) => api && api.status === 403,
    investigation: (api) => ({
      rootCause: 'Authorization Failure — Missing Oracle Role or Privilege',
      pattern: 'AUTH_FAILURE_403',
      evidence: [
        `HTTP Status: 403 Forbidden`,
        `User is authenticated but not authorized for this resource`,
        `Oracle Cloud returned 403 — user lacks required duty/job/data role`,
      ],
      possibleCauses: [
        'Missing Duty Role (e.g., "Item Management Specialist")',
        'Missing Job Role (e.g., "Procurement Manager")',
        'Missing Data Role (e.g., Inventory Organization ORG-001)',
        'Endpoint requires specific Oracle privilege not assigned',
        'API version changed — privilege requirements updated',
      ],
      recommendations: [
        { action: 'Check user\'s assigned roles in Oracle Identity Management', priority: 'HIGH', why: 'Oracle does not reveal which role is missing in 403 error' },
        { action: 'Verify endpoint privilege requirements in Oracle Cloud documentation', priority: 'HIGH', why: 'Each REST endpoint has specific privilege requirements' },
        { action: 'Add error handling: if (responseCode == 403) { setStatusMessage("Access Denied", "Contact administrator") }', priority: 'MEDIUM', why: 'Provide clear user feedback instead of crash' },
        { action: 'Check if token is expired (401 vs 403 distinction)', priority: 'LOW', why: '403 = wrong role, 401 = expired session — different fixes' },
      ],
      loggerSuggestion: 'logger.error("Authorization failed for API: " + apiName + " — HTTP 403");\nlogger.error("User: " + currentUser + " — Missing required role for: " + endpoint);',
      confidence: 97,
      nextSteps: 'Ask user: What roles are assigned to your account? Then check Oracle Cloud docs for the endpoint.',
    }),
  },

  AUTH_FAILURE_401: {
    id: 'AUTH_FAILURE_401',
    name: 'Authentication Failure (HTTP 401)',
    description: 'User session expired or token is invalid/missing.',
    icon: '🔑',
    severity: 'HIGH',
    color: '#DC2626',
    detect: (api) => api && api.status === 401,
    investigation: (api) => ({
      rootCause: 'Authentication Failure — Session Expired or Invalid Token',
      pattern: 'AUTH_FAILURE_401',
      evidence: [
        'HTTP Status: 401 Unauthorized',
        'No valid session token found or token has expired',
        'User must re-authenticate',
      ],
      possibleCauses: [
        'Session token expired (usually after 8-12 hours)',
        'Authorization header missing from request',
        'Token format is invalid or corrupted',
        'Simultaneous login from another device invalidated current session',
      ],
      recommendations: [
        { action: 'Re-login to Oracle Fusion to refresh session token', priority: 'HIGH', why: 'Token expiry is most common cause of 401' },
        { action: 'Add token refresh logic before calling API', priority: 'MEDIUM', why: 'Prevents user disruption on session timeout' },
        { action: 'Add: if (responseCode == 401) { redirectToLogin() }', priority: 'MEDIUM', why: 'Gracefully redirect user instead of crash' },
      ],
      loggerSuggestion: 'logger.error("Authentication failed: HTTP 401 for API: " + apiName);\nlogger.error("Session may have expired — user should re-login");',
      confidence: 95,
      nextSteps: 'Ask user to log out and log back in. If issue persists, check Oracle session timeout configuration.',
    }),
  },

  SERVER_ERROR_500: {
    id: 'SERVER_ERROR_500',
    name: 'Server Error (HTTP 500)',
    description: 'Oracle backend threw an unhandled exception. This is a server-side problem, not a client configuration issue.',
    icon: '💥',
    severity: 'CRITICAL',
    color: '#7C3AED',
    detect: (api) => api && api.status === 500,
    investigation: (api) => ({
      rootCause: 'Oracle Server Error — Unhandled Exception in Backend',
      pattern: 'SERVER_ERROR_500',
      evidence: [
        'HTTP Status: 500 Internal Server Error',
        'Oracle backend threw an unhandled exception',
        'Error may be visible in Oracle Cloud error logs',
      ],
      possibleCauses: [
        'Invalid request payload triggered server-side exception',
        'Oracle backend bug or regression',
        'Database constraint violation on the server',
        'Concurrent update conflict',
      ],
      recommendations: [
        { action: 'Check Oracle Cloud error logs (APEX Performance Hub or Oracle Support)', priority: 'HIGH', why: 'Root cause is on the server — need server logs' },
        { action: 'Log the exact request payload that triggered 500', priority: 'HIGH', why: 'Reproduce the issue precisely' },
        { action: 'Retry the operation to check if it is transient or persistent', priority: 'MEDIUM', why: 'Transient 500s often resolve on retry' },
        { action: 'Contact Oracle Support with the exact API call and timestamp', priority: 'HIGH', why: '500 is a server-side issue that Oracle must fix' },
      ],
      loggerSuggestion: 'logger.error("Server Error 500 from: " + apiName);\nlogger.error("Request sent: " + JSON.stringify(payload));\nlogger.error("Raw response: " + responseBody);',
      confidence: 88,
      nextSteps: 'Capture the exact request payload and timestamp. Report to Oracle Support with the API name and error details.',
    }),
  },

  SERVICE_DOWN_503: {
    id: 'SERVICE_DOWN_503',
    name: 'Service Unavailable (HTTP 503)',
    description: 'Oracle Cloud service is temporarily down for maintenance or experiencing an outage.',
    icon: '🚧',
    severity: 'CRITICAL',
    color: '#DC2626',
    detect: (api) => api && api.status === 503,
    investigation: (api) => ({
      rootCause: 'Oracle Service Unavailable — Maintenance Window or Cloud Outage',
      pattern: 'SERVICE_DOWN_503',
      evidence: [
        'HTTP Status: 503 Service Unavailable',
        'Oracle Cloud infrastructure is temporarily unreachable',
      ],
      possibleCauses: [
        'Planned Oracle Cloud maintenance window',
        'Unplanned Oracle Cloud outage',
        'Network connectivity issue between client and Oracle',
        'Load balancer / proxy configuration issue',
      ],
      recommendations: [
        { action: 'Check Oracle Cloud Status page: cloud.oracle.com/status', priority: 'HIGH', why: 'Confirm if it is an Oracle-wide outage' },
        { action: 'Wait for maintenance window to end and retry', priority: 'HIGH', why: '503 is typically temporary' },
        { action: 'Add retry logic with exponential backoff', priority: 'MEDIUM', why: '503 should retry after Retry-After header delay' },
      ],
      loggerSuggestion: 'logger.error("Service Unavailable (503): " + apiName + " — Oracle may be in maintenance");\nsetStatusMessage("Service Unavailable", "Please retry in a few minutes", "error");',
      confidence: 92,
      nextSteps: 'Check oracle.com/status. Wait 15 minutes and retry. If persistent, contact Oracle Cloud Support.',
    }),
  },

  GATEWAY_TIMEOUT_504: {
    id: 'GATEWAY_TIMEOUT_504',
    name: 'Gateway Timeout (HTTP 504)',
    description: 'Oracle took too long to respond. Usually caused by slow SQL query or heavy server load.',
    icon: '⏱',
    severity: 'HIGH',
    color: '#F59E0B',
    detect: (api) => api && (api.status === 504 || api.ms > 30000),
    investigation: (api) => ({
      rootCause: `Gateway Timeout — Oracle Query Took Too Long (${api.ms}ms)`,
      pattern: 'GATEWAY_TIMEOUT_504',
      evidence: [
        `HTTP Status: ${api.status || 'Timeout'}`,
        `Response time: ${api.ms}ms (threshold: 30,000ms)`,
        'Query or processing took longer than the gateway timeout',
      ],
      possibleCauses: [
        'Slow SQL query without proper index',
        'Too many records returned without pagination',
        'Oracle Cloud under heavy load',
        'Network latency spike',
      ],
      recommendations: [
        { action: 'Check Oracle APEX Performance Hub for slow SQL queries', priority: 'HIGH', why: 'Identify the slow query execution plan' },
        { action: 'Add LIMIT/pagination to reduce data returned per call', priority: 'HIGH', why: 'Reduce query scope to prevent timeout' },
        { action: 'Add retry logic on timeout', priority: 'MEDIUM', why: 'Transient timeouts should retry automatically' },
      ],
      loggerSuggestion: 'logger.warn("API " + apiName + " took " + ms + "ms — threshold exceeded");\nlogger.trace("Query parameters: " + JSON.stringify(payload) + " — consider adding pagination");',
      confidence: 85,
      nextSteps: 'Open Oracle APEX Performance Hub → SQL Monitoring. Find the query matching this API call timestamp.',
    }),
  },

  NOT_FOUND_404: {
    id: 'NOT_FOUND_404',
    name: 'Endpoint Not Found (HTTP 404)',
    description: 'API endpoint does not exist. URL may be wrong or API version changed.',
    icon: '🔍',
    severity: 'HIGH',
    color: '#DC2626',
    detect: (api) => api && api.status === 404,
    investigation: (api) => ({
      rootCause: 'API Endpoint Not Found — Wrong URL or Version Mismatch',
      pattern: 'NOT_FOUND_404',
      evidence: [
        'HTTP Status: 404 Not Found',
        `Endpoint attempted: ${api.endpoint || 'Unknown'}`,
        'Resource does not exist at this URL',
      ],
      possibleCauses: [
        'API URL is incorrect or has a typo',
        'API version changed (/v1/ → /v2/)',
        'Oracle REST endpoint was renamed or deprecated',
        'Resource ID in URL does not exist',
      ],
      recommendations: [
        { action: 'Verify the endpoint URL against Oracle Cloud API documentation', priority: 'HIGH', why: 'Confirm correct URL format and version' },
        { action: 'Check if Oracle migrated from /v1/ to /v2/ endpoints', priority: 'HIGH', why: 'Common cause after Oracle Cloud updates' },
        { action: 'Log the full URL before calling: logger.trace("URL = " + fullUrl)', priority: 'MEDIUM', why: 'Verify exact URL being called' },
      ],
      loggerSuggestion: 'logger.error("404 Not Found: " + apiName + " — Endpoint: " + url);\nlogger.error("Check API documentation for correct URL and version");',
      confidence: 90,
      nextSteps: 'Check Oracle REST API documentation for the correct endpoint URL. Test manually using Postman or curl.',
    }),
  },

  BAD_REQUEST_400: {
    id: 'BAD_REQUEST_400',
    name: 'Bad Request (HTTP 400)',
    description: 'Request payload is malformed, missing required fields, or contains invalid values.',
    icon: '⚠️',
    severity: 'HIGH',
    color: '#F59E0B',
    detect: (api) => api && api.status === 400,
    investigation: (api) => ({
      rootCause: 'Malformed Request — Missing or Invalid Fields in Payload',
      pattern: 'BAD_REQUEST_400',
      evidence: [
        'HTTP Status: 400 Bad Request',
        'Oracle rejected the request due to validation failure',
        'Check request payload for missing or invalid values',
      ],
      possibleCauses: [
        'Missing required field in request body',
        'Field value is wrong type (string vs number)',
        'Field value exceeds maximum length constraint',
        'Business validation rule rejected the value',
      ],
      recommendations: [
        { action: 'Log the full request payload before sending', priority: 'HIGH', why: 'See exactly what was sent that Oracle rejected' },
        { action: 'Add client-side validation before API call', priority: 'HIGH', why: 'Catch invalid data before it reaches Oracle' },
        { action: 'Parse 400 response body for field-level error messages', priority: 'MEDIUM', why: 'Oracle 400 responses usually contain which field failed' },
      ],
      loggerSuggestion: 'logger.error("Bad Request 400 from: " + apiName);\nlogger.error("Payload sent: " + JSON.stringify(payload));\nlogger.error("Response error: " + responseBody);',
      confidence: 88,
      nextSteps: 'Log the exact request payload. Compare each field against Oracle API documentation to find the invalid/missing field.',
    }),
  },

  SLOW_API: {
    id: 'SLOW_API',
    name: 'Slow API Response',
    description: 'API responded but took longer than 2000ms. Performance degradation detected.',
    icon: '🐢',
    severity: 'MEDIUM',
    color: '#F59E0B',
    detect: (api) => api && api.status === 200 && api.ms > 2000,
    investigation: (api) => ({
      rootCause: `Performance Degradation — API "${api.name}" took ${api.ms}ms`,
      pattern: 'SLOW_API',
      evidence: [
        `Response time: ${api.ms}ms (threshold: 2000ms)`,
        'API returned successfully but with elevated latency',
        `${api.ms > 5000 ? 'CRITICAL' : 'WARNING'}: Response time ${api.ms > 5000 ? 'exceeds 5 seconds' : 'between 2-5 seconds'}`,
      ],
      possibleCauses: [
        'Oracle backend SQL query not optimized (missing index)',
        'Too many records returned without pagination',
        'Oracle Cloud server under heavy load',
        'Large data volume being processed without batching',
      ],
      recommendations: [
        { action: 'Add pagination: limit=100&offset=0 to reduce data per call', priority: 'HIGH', why: 'Prevents fetching all records at once' },
        { action: 'Check Oracle APEX Performance Hub for slow SQL at this timestamp', priority: 'HIGH', why: 'Find the exact slow query' },
        { action: 'Add response time logging: logger.trace("API took: " + ms + "ms")', priority: 'MEDIUM', why: 'Track performance trends over time' },
      ],
      loggerSuggestion: `logger.warn("Slow API: ${api.name} took ${api.ms}ms");\nlogger.trace("Consider adding pagination or optimizing query");`,
      confidence: 80,
      nextSteps: 'Add pagination parameters. Monitor in Oracle APEX for slow query execution.',
    }),
  },

  SCOPE_MISMATCH: {
    id: 'SCOPE_MISMATCH',
    name: 'Session/Object Scope Mismatch',
    description: 'Variable was stored in session scope but read from object scope (or vice versa), resulting in null.',
    icon: '🎯',
    severity: 'HIGH',
    color: '#7C3AED',
    detect: (msg) => {
      if (!msg) return false;
      return /putSessionObject.*getObject|getObject.*putSession|session.*scope.*null|object.*scope.*null/i.test(msg);
    },
    investigation: (msg) => ({
      rootCause: 'Scope Mismatch — Variable Set in Session Scope, Read from Object Scope',
      pattern: 'SCOPE_MISMATCH',
      evidence: [
        'Variable is null when it should have a value',
        'Mismatch detected between putObject/getObject scope calls',
        'Common silent bug: putSessionObject() + getObject() = null',
      ],
      possibleCauses: [
        'putSessionObject() used to store, getObject() used to retrieve',
        'putObject() used to store, getSessionObject() used to retrieve',
        'Object was cleared between screens',
        'Variable name typo between put and get calls',
      ],
      recommendations: [
        { action: 'Check all flexi.putObject() and flexi.getObject() pairs use same scope', priority: 'HIGH', why: 'Scope mismatch is the most common null object bug' },
        { action: 'Add logger.trace("Object value: " + flexi.getObject("key")) before use', priority: 'HIGH', why: 'Confirm value is present before use' },
        { action: 'Use consistent scope (object scope for in-page, session scope for cross-page)', priority: 'MEDIUM', why: 'Design principle to prevent future scope bugs' },
      ],
      loggerSuggestion: 'logger.trace("Checking scope: sessionObj=" + flexi.getSessionObject("key") + " objScope=" + flexi.getObject("key"));',
      confidence: 75,
      nextSteps: 'Search code for all uses of the null variable. Check if put/get calls use different scope methods.',
    }),
  },

  NULL_POINTER: {
    id: 'NULL_POINTER',
    name: 'Null Reference Exception',
    description: 'Code tried to call a method on a null object. Object was never initialized or was unexpectedly null.',
    icon: '❌',
    severity: 'CRITICAL',
    color: '#DC2626',
    detect: (msg) => msg && /NullPointerException|Cannot read prop.*null|null.*length|null.*getMessage/i.test(msg),
    investigation: (msg) => ({
      rootCause: 'NullPointerException — Accessing Property on Null Object',
      pattern: 'NULL_POINTER',
      evidence: [
        'NullPointerException thrown at runtime',
        'Code tried to call method/access property on null object',
        'Null check was missing before object usage',
      ],
      possibleCauses: [
        'API returned null or empty response (Blank API)',
        'Session/object scope mismatch causing null value',
        'Required LOV selection was skipped by user',
        'Object was never initialized before first use',
      ],
      recommendations: [
        { action: 'Add null check: if (obj != null) { obj.getMethod() }', priority: 'HIGH', why: 'Prevent crash when object is null' },
        { action: 'Log object state before use: logger.trace("Object value: " + obj)', priority: 'HIGH', why: 'Confirm what value the object had before crash' },
        { action: 'Check API response — if API returned null, handle gracefully', priority: 'HIGH', why: 'API null response is the most common root cause' },
      ],
      loggerSuggestion: 'if (obj == null) {\n  logger.error("Object is null — cannot proceed");\n  setStatusMessage("Error", "Required data is missing", "error");\n  return;\n}',
      confidence: 80,
      nextSteps: 'Add logger.trace() before the null access. Rerun log to see what value was present. Check API response body.',
    }),
  },

  MISSING_LOGGER: {
    id: 'MISSING_LOGGER',
    name: 'Missing Logger / Telemetry Gap',
    description: 'Key instrumentation points are missing. Cannot determine what happened between log entries.',
    icon: '📊',
    severity: 'LOW',
    color: '#6B7280',
    detect: (gap) => gap && gap.type === 'Missing API Response Logger',
    investigation: () => ({
      rootCause: 'Insufficient Logging — Cannot Trace Execution Path',
      pattern: 'MISSING_LOGGER',
      evidence: [
        'Log sequence has unexplained gaps',
        'Key processing steps have no trace output',
        'Cannot determine root cause without more instrumentation',
      ],
      possibleCauses: [
        'Logger.trace() calls were not added during development',
        'Debug logging is disabled in this environment',
        'Error occurred in a code path with no logging',
      ],
      recommendations: [
        { action: 'Add logger.trace() at: API call start, response received, data parsed, validation result', priority: 'HIGH', why: 'Without these 4 points, you cannot trace API failures' },
        { action: 'Add logger.trace("Response Body: " + responseBody) after every API call', priority: 'HIGH', why: 'Most critical — always log what the API returned' },
        { action: 'Enable DEBUG log level in environment configuration', priority: 'MEDIUM', why: 'May unlock existing debug log statements' },
      ],
      loggerSuggestion: '// Add these at key points:\nlogger.trace("Calling API: " + apiName);\nlogger.trace("Response Code: " + responseCode);\nlogger.trace("Response Body: " + responseBody);\nlogger.trace("Parsed items: " + (items ? items.length : "null"));',
      confidence: 60,
      nextSteps: 'Add logger.trace() at the 4 critical points above. Rerun the failing scenario to get visibility.',
    }),
  },
};

// ─── Investigation Engine (7-phase methodology from investigation_engine.md) ──
class LogRadarInvestigator {
  constructor() {
    this.evidence = [];
    this.confidence = 0;
    this.pattern = null;
  }

  // Reset for new investigation
  reset() {
    this.evidence = [];
    this.confidence = 0;
    this.pattern = null;
  }

  // Phase 1: Establish Context
  establishContext(api, logEntries) {
    const context = {
      apiName: api.name || 'Unknown API',
      endpoint: api.endpoint || 'Unknown',
      method: api.method || 'Unknown',
      status: api.status || 'Unknown',
      responseTime: api.ms || 0,
      thread: api.thread || 'Unknown',
      timestamp: api.timestamp || 'Unknown',
      hasRequest: !!api.request,
      hasResponse: !!api.response,
      recordCount: api.recordCount,
    };
    return context;
  }

  // Phase 2: Parse the Log — extract key data points
  parseLog(api) {
    const facts = [];

    if (api.status) facts.push({ label: 'HTTP Status', value: String(api.status), significance: api.status >= 400 ? 'HIGH' : 'NORMAL' });
    if (api.ms) facts.push({ label: 'Response Time', value: `${api.ms}ms`, significance: api.ms > 5000 ? 'HIGH' : api.ms > 2000 ? 'MEDIUM' : 'NORMAL' });
    if (api.endpoint) facts.push({ label: 'Endpoint', value: api.endpoint, significance: 'NORMAL' });
    if (api.method) facts.push({ label: 'HTTP Method', value: api.method, significance: 'NORMAL' });
    if (api.response) {
      facts.push({ label: 'Response Body', value: api.response.substring(0, 200) + (api.response.length > 200 ? '...' : ''), significance: 'NORMAL' });
    } else {
      facts.push({ label: 'Response Body', value: 'NOT CAPTURED — Add logger.trace("Response Body: " + responseBody)', significance: 'HIGH' });
    }
    if (api.recordCount !== null && api.recordCount !== undefined) {
      facts.push({ label: 'Record Count', value: String(api.recordCount), significance: api.recordCount === 0 ? 'HIGH' : 'NORMAL' });
    }
    if (api.retryCount > 0) {
      facts.push({ label: 'Retry Count', value: String(api.retryCount), significance: 'MEDIUM' });
    }

    return facts;
  }

  // Phase 3: Classify Pattern
  classifyPattern(api) {
    for (const [key, pattern] of Object.entries(BRAIN_PATTERNS)) {
      if (pattern.detect && typeof pattern.detect === 'function') {
        if (pattern.detect(api)) {
          return pattern;
        }
      }
    }
    // Default healthy pattern
    return {
      id: 'HEALTHY',
      name: 'Healthy API Call',
      description: 'API call completed successfully with valid response.',
      icon: '✅',
      severity: 'LOW',
      color: '#16A34A',
    };
  }

  // Phase 4: Accumulate Evidence and Score Confidence
  accumulateEvidence(api, pattern) {
    const evidence = [];
    let confidence = 50;

    if (api.status && api.status !== 200) {
      const httpLabel = {
        400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
        404: 'Not Found', 500: 'Server Error', 503: 'Service Unavailable',
        504: 'Gateway Timeout',
      }[api.status] || `HTTP ${api.status}`;
      evidence.push({ text: `HTTP ${api.status} ${httpLabel} confirmed in log`, strength: 'STRONG' });
      confidence += 30;
    }

    if (api.response) {
      evidence.push({ text: 'Response body captured in log', strength: 'STRONG' });
      confidence += 15;
      if (pattern.id === 'BLANK_API' && /\"count\"\s*:\s*0/i.test(api.response)) {
        evidence.push({ text: 'Response confirms count=0 (zero records)', strength: 'STRONG' });
        confidence += 20;
      }
      if (pattern.id === 'BLANK_API' && /\"items\"\s*:\s*\[\s*\]/i.test(api.response)) {
        evidence.push({ text: 'Response confirms items=[] (empty array)', strength: 'STRONG' });
        confidence += 15;
      }
    } else {
      evidence.push({ text: 'Response body NOT captured — instrumentation gap', strength: 'WEAK' });
      confidence -= 10;
    }

    if (api.ms > 5000) {
      evidence.push({ text: `Response time ${api.ms}ms is critically high (>5s)`, strength: 'STRONG' });
      confidence += 10;
    } else if (api.ms > 2000) {
      evidence.push({ text: `Response time ${api.ms}ms is elevated (>2s)`, strength: 'MEDIUM' });
      confidence += 5;
    }

    if (api.recordCount === 0) {
      evidence.push({ text: 'Zero records returned (extracted from response)', strength: 'STRONG' });
      if (pattern.id === 'BLANK_API') confidence += 15;
    }

    if (api.retryCount > 0) {
      evidence.push({ text: `API was retried ${api.retryCount} time(s)`, strength: 'MEDIUM' });
      confidence += 5;
    }

    if (!api.endpoint) {
      evidence.push({ text: 'Endpoint URL not captured in log — add logger.trace("URL = " + url)', strength: 'WEAK' });
    } else {
      evidence.push({ text: `Endpoint confirmed: ${api.endpoint.substring(0, 80)}`, strength: 'MEDIUM' });
      confidence += 5;
    }

    return { evidence, confidence: Math.min(98, Math.max(30, confidence)) };
  }

  // Full Investigation: Run all phases and return structured report
  investigateAPI(api) {
    if (!api) return null;
    this.reset();

    // Phase 1: Context
    const context = this.establishContext(api);

    // Phase 2: Parse log
    const facts = this.parseLog(api);

    // Phase 3: Pattern Classification
    const pattern = this.classifyPattern(api);

    // Phase 4: Evidence accumulation
    const { evidence, confidence } = this.accumulateEvidence(api, pattern);

    // Phase 5: Get pattern-specific investigation details
    let investigation = null;
    if (pattern.id !== 'HEALTHY' && pattern.investigation) {
      investigation = pattern.investigation(api);
    }

    // Phase 6: Build timeline
    const timeline = this.buildApiTimeline(api);

    // Phase 7: Final report
    return {
      pattern,
      context,
      facts,
      evidence,
      confidence: investigation ? investigation.confidence || confidence : confidence,
      investigation,
      timeline,
      apiName: api.name,
      businessResult: api.businessResult || 'Unknown',
    };
  }

  buildApiTimeline(api) {
    const steps = [];
    steps.push({ step: 'T1', label: `API call initiated: ${api.name}`, status: 'done', detail: `Method: ${api.method || 'GET'} | Thread: ${api.thread || 'N/A'}` });
    if (api.endpoint) {
      steps.push({ step: 'T2', label: 'Request sent to endpoint', status: 'done', detail: api.endpoint.substring(0, 100) });
    }
    if (api.request) {
      steps.push({ step: 'T3', label: 'Request payload attached', status: 'done', detail: api.request.substring(0, 100) });
    }
    if (api.ms) {
      steps.push({ step: 'T4', label: `Response received (${api.ms}ms)`, status: api.ms > 2000 ? 'slow' : 'done', detail: `HTTP ${api.status || 'Unknown'}` });
    }
    if (api.response) {
      steps.push({ step: 'T5', label: 'Response body parsed', status: 'done', detail: api.response.substring(0, 100) });
    } else {
      steps.push({ step: 'T5', label: 'Response body — NOT LOGGED', status: 'missing', detail: 'Add logger.trace("Response Body: " + responseBody)' });
    }
    if (api.status >= 400) {
      steps.push({ step: 'T6', label: `API FAILED with HTTP ${api.status}`, status: 'error', detail: BRAIN_PATTERNS[Object.keys(BRAIN_PATTERNS).find(k => BRAIN_PATTERNS[k].detect && BRAIN_PATTERNS[k].detect(api))]?.name || 'Error' });
    } else if (api.recordCount === 0) {
      steps.push({ step: 'T6', label: 'Zero records returned (Blank API)', status: 'warn', detail: 'Business failure — API succeeded but no data found' });
    } else {
      steps.push({ step: 'T6', label: 'API completed successfully', status: 'done', detail: api.recordCount !== null ? `${api.recordCount} records` : 'Records unknown' });
    }
    return steps;
  }
}

// ─── Confidence Engine ────────────────────────────────────────────────────────
const CONFIDENCE_ENGINE = {
  THRESHOLDS: {
    HIGH:   80,  // Multiple strong evidence points, clear root cause
    MEDIUM: 50,  // Root cause identified but needs confirmation
    LOW:    30,  // Speculative, multiple possible causes
  },

  getLabel(confidence) {
    if (confidence >= this.THRESHOLDS.HIGH)   return { label: 'HIGH',   color: '#16A34A', icon: '🟢' };
    if (confidence >= this.THRESHOLDS.MEDIUM) return { label: 'MEDIUM', color: '#F59E0B', icon: '🟡' };
    return                                           { label: 'LOW',    color: '#DC2626', icon: '🔴' };
  },

  getBoostActions(confidence, context) {
    const actions = [];
    if (!context) {
      if (confidence < this.THRESHOLDS.MEDIUM) {
        actions.push('Add logger.trace() for request payload and response body');
        actions.push('Provide the exact API name and endpoint URL');
      }
      if (confidence < this.THRESHOLDS.HIGH) {
        actions.push('Share the full log context surrounding the error');
        actions.push('Confirm what the user was doing when the error occurred');
      }
      return actions;
    }

    const isApi = context.endpoint !== undefined || context.status !== undefined;
    if (isApi) {
      if (!context.request || context.request === 'N/A' || context.request === 'NOT LOGGED') {
        actions.push('Missing Request Payload. Recommendation: Add logger.trace("Request Payload: " + payload)');
      }
      if (!context.response || context.response === 'N/A' || context.response === 'NOT LOGGED') {
        actions.push('Missing Response Body. Recommendation: Add logger.trace("Response Body: " + getRawResponse())');
      }
      if (!context.endpoint) {
        actions.push('Missing Endpoint URL. Recommendation: Add logger.trace("URL = " + url)');
      }
      if (!context.correlationId) {
        actions.push('Missing Correlation ID. Recommendation: Add logger.trace("Correlation ID: " + correlationId)');
      }
    } else {
      const msg = context.message || '';
      if (!/at\s+[a-zA-Z0-9_\.]+\([a-zA-Z0-9_\.]+\.java:\d+\)/.test(msg) && !/TargetError|Exception/i.test(msg)) {
        actions.push('Missing Exception Stack Trace. Recommendation: Ensure exceptions are logged with printStackTrace() or logger.error(msg, e)');
      }
      if (window.STATE && window.STATE.screenDefinition) {
         const screenDef = window.STATE.screenDefinition;
         if (screenDef.fields) {
            let total = Object.keys(screenDef.fields).length;
            let logged = 0;
            for (const events of Object.values(screenDef.fields)) {
               for (const ev of Object.values(events)) {
                  if (ev && ev.code && /logger\./i.test(ev.code)) {
                     logged++;
                     break;
                  }
               }
            }
            if (total > 0 && (logged / total) < 0.5) {
               actions.push(`Low Field Logger Coverage (${Math.round((logged/total)*100)}%). Recommendation: Add logger statements to screen fields.`);
            }
         }
      }
    }

    if (actions.length === 0 && confidence < this.THRESHOLDS.HIGH) {
      actions.push('Share the full log context surrounding the error');
    }
    return actions;
  },
};

// ─── Enhanced Row Investigation (integrates with analyzeRow) ─────────────────
function brainInvestigateRow(row, allRows, analysisData) {
  const msg = row.message;
  const results = {
    pattern: null,
    evidence: [],
    confidence: 50,
    brainRootCause: null,
    recommendations: [],
    loggerSuggestions: [],
    nextSteps: null,
    investigationPhases: [],
  };

  // Classify message-level patterns
  if (/NullPointerException|cannot read prop.*null/i.test(msg)) {
    const p = BRAIN_PATTERNS.NULL_POINTER;
    const inv = p.investigation(msg);
    results.pattern = p;
    results.evidence = inv.evidence;
    results.confidence = inv.confidence;
    results.brainRootCause = inv.rootCause;
    results.recommendations = inv.recommendations;
    results.loggerSuggestions = [inv.loggerSuggestion];
    results.nextSteps = inv.nextSteps;
    results.investigationPhases = [
      'Phase 1: Classified as NullPointerException',
      'Phase 2: Log message confirms null object access',
      'Phase 5: Most likely caused by null API response or scope mismatch',
    ];
  }

  else if (/Response Code\s*[=:]\s*403/i.test(msg) || /HTTP.*403|403.*Forbidden/i.test(msg)) {
    const p = BRAIN_PATTERNS.AUTH_FAILURE_403;
    const inv = p.investigation({ name: 'API', status: 403, endpoint: null, ms: 0 });
    results.pattern = p;
    results.evidence = inv.evidence;
    results.confidence = inv.confidence;
    results.brainRootCause = inv.rootCause;
    results.recommendations = inv.recommendations;
    results.loggerSuggestions = [inv.loggerSuggestion];
    results.nextSteps = inv.nextSteps;
    results.investigationPhases = [
      'Phase 1: HTTP 403 Forbidden detected',
      'Phase 4: Authorization failure confirmed — not an API bug',
      'Phase 7: Missing Oracle role assignment (Duty/Job/Data role)',
    ];
  }

  else if (/Response Code\s*[=:]\s*401/i.test(msg) || /HTTP.*401|401.*Unauthorized/i.test(msg)) {
    const p = BRAIN_PATTERNS.AUTH_FAILURE_401;
    const inv = p.investigation({ name: 'API', status: 401, endpoint: null, ms: 0 });
    results.pattern = p;
    results.evidence = inv.evidence;
    results.confidence = inv.confidence;
    results.brainRootCause = inv.rootCause;
    results.recommendations = inv.recommendations;
    results.loggerSuggestions = [inv.loggerSuggestion];
    results.nextSteps = inv.nextSteps;
    results.investigationPhases = [
      'Phase 1: HTTP 401 Unauthorized detected',
      'Phase 4: Authentication token invalid or expired',
      'Phase 7: User must re-login to refresh session',
    ];
  }

  else if (/Response Code\s*[=:]\s*503/i.test(msg) || /503.*service unavailable/i.test(msg)) {
    const p = BRAIN_PATTERNS.SERVICE_DOWN_503;
    const inv = p.investigation({ name: 'API', status: 503, ms: 0 });
    results.pattern = p;
    results.evidence = inv.evidence;
    results.confidence = inv.confidence;
    results.brainRootCause = inv.rootCause;
    results.recommendations = inv.recommendations;
    results.loggerSuggestions = [inv.loggerSuggestion];
    results.nextSteps = inv.nextSteps;
    results.investigationPhases = [
      'Phase 1: HTTP 503 Service Unavailable detected',
      'Phase 2: Oracle Cloud infrastructure issue',
      'Phase 7: Wait for maintenance to complete',
    ];
  }

  else if (/putSessionObject.*getObject|getObject.*null|session.*scope|scope.*mismatch/i.test(msg)) {
    const p = BRAIN_PATTERNS.SCOPE_MISMATCH;
    const inv = p.investigation(msg);
    results.pattern = p;
    results.evidence = inv.evidence;
    results.confidence = inv.confidence;
    results.brainRootCause = inv.rootCause;
    results.recommendations = inv.recommendations;
    results.loggerSuggestions = [inv.loggerSuggestion];
    results.nextSteps = inv.nextSteps;
    results.investigationPhases = [
      'Phase 1: Session/Object scope pattern detected',
      'Phase 4: put/get scope mismatch is silent null cause',
      'Phase 7: Align all put/get calls to use same scope',
    ];
  }

  else {
    // Generic investigation using available evidence
    results.investigationPhases = [
      'Phase 1: Log entry classified and analyzed',
      'Phase 2: Context gathered from surrounding log lines',
      'Phase 3: No specific pattern matched — generic investigation',
    ];

    // Build generic evidence from log message
    const errM = msg.match(/Exception|Error|FATAL/i);
    if (errM) {
      results.evidence.push({ text: `Exception/error keyword detected: ${errM[0]}`, strength: 'STRONG' });
      results.confidence = 55;
    }

    const statusM = msg.match(/Response Code\s*[=:]\s*(\d+)/i);
    if (statusM) {
      const status = parseInt(statusM[1]);
      results.evidence.push({ text: `HTTP Status ${status} detected in log`, strength: 'STRONG' });
      results.confidence += (status >= 400 ? 20 : 5);
    }

    results.brainRootCause = 'Investigate the log entry context using the 7-phase methodology. Check API response, exception type, and scope of affected objects.';
    results.recommendations = [
      { action: 'Add logger.trace() before and after the failing code section', priority: 'HIGH', why: 'Increase visibility into execution path' },
      { action: 'Check preceding log lines for API calls or setup code', priority: 'HIGH', why: 'Root cause often occurs several lines before the error' },
      { action: 'Identify the exact line number from stack trace if available', priority: 'MEDIUM', why: 'Pinpoints exact code location' },
    ];
    results.loggerSuggestions = ['logger.trace("Starting section: [describe what this code does]");\nlogger.trace("State before: " + JSON.stringify(relevantObject));'];
    results.nextSteps = 'Expand the "Preceding Log Context" accordion below to trace events leading to this error.';
  }

  return results;
}

// ─── Public API ───────────────────────────────────────────────────────────────
const LOGRADAR_BRAIN = {
  version: '1.0',
  investigator: new LogRadarInvestigator(),
  PATTERNS: BRAIN_PATTERNS,
  CONFIDENCE: CONFIDENCE_ENGINE,

  // Main entry: investigate a single API call
  investigateAPI(api) {
    return this.investigator.investigateAPI(api);
  },

  // Main entry: investigate a log row
  investigateRow(row, allRows, analysisData) {
    return brainInvestigateRow(row, allRows, analysisData);
  },

  // Classify a pattern by type
  classifyApiPattern(api) {
    return this.investigator.classifyPattern(api);
  },

  // Get confidence label
  getConfidenceLabel(score) {
    return CONFIDENCE_ENGINE.getLabel(score);
  },

  // Build the HTML for a brain investigation panel
  renderBrainPanel(result) {
    if (!result) return '<div style="color:#9CA3AF;padding:12px;">No investigation data available.</div>';

    const conf = CONFIDENCE_ENGINE.getLabel(result.confidence);
    const boostActions = CONFIDENCE_ENGINE.getBoostActions(result.confidence, result.api || result);

    // Evidence rows
    const evidenceHTML = (result.evidence || []).map(e => {
      const icon = e.strength === 'STRONG' ? '🔵' : e.strength === 'WEAK' ? '🔘' : '🟡';
      return `<div class="brain-evidence-row">
        <span class="brain-evidence-icon">${icon}</span>
        <span class="brain-evidence-text">${escHtml ? escHtml(e.text) : e.text}</span>
        <span class="brain-evidence-strength brain-strength-${(e.strength || 'MEDIUM').toLowerCase()}">${e.strength || 'MEDIUM'}</span>
      </div>`;
    }).join('');

    // Recommendations
    const recsHTML = (result.investigation?.recommendations || result.recommendations || []).map((r, i) => `
      <div class="brain-rec-item">
        <div class="brain-rec-priority brain-priority-${(r.priority || 'MEDIUM').toLowerCase()}">${r.priority || 'MEDIUM'}</div>
        <div class="brain-rec-content">
          <div class="brain-rec-action">${escHtml ? escHtml(r.action) : r.action}</div>
          <div class="brain-rec-why">Why: ${escHtml ? escHtml(r.why) : r.why}</div>
        </div>
      </div>`).join('');

    // Timeline steps
    const timelineHTML = (result.timeline || []).map(step => {
      const dot = step.status === 'error' ? '🔴' : step.status === 'warn' ? '🟡' : step.status === 'missing' ? '⚪' : step.status === 'slow' ? '🟠' : '🟢';
      return `<div class="brain-timeline-step">
        <span class="brain-timeline-dot">${dot}</span>
        <span class="brain-timeline-label">[${step.step}] ${escHtml ? escHtml(step.label) : step.label}</span>
        ${step.detail ? `<span class="brain-timeline-detail">${escHtml ? escHtml(step.detail) : step.detail}</span>` : ''}
      </div>`;
    }).join('');

    // Logger suggestion
    const loggerCode = result.investigation?.loggerSuggestion || (result.loggerSuggestions || [])[0] || '';
    const loggerHTML = loggerCode ? `
      <div class="brain-logger-block">
        <div class="brain-logger-title">📝 Recommended Logger Placement</div>
        <pre class="brain-logger-code">${escHtml ? escHtml(loggerCode) : loggerCode}</pre>
      </div>` : '';

    // Possible causes
    const causesHTML = (result.investigation?.possibleCauses || []).map(c =>
      `<li class="brain-cause-item">${escHtml ? escHtml(c) : c}</li>`
    ).join('');

    // Confidence boost actions
    const boostHTML = boostActions.length ? `
      <div class="brain-boost-block">
        <div class="brain-boost-title">⬆️ To increase confidence to HIGH:</div>
        ${boostActions.map(a => `<div class="brain-boost-item">→ ${escHtml ? escHtml(a) : a}</div>`).join('')}
      </div>` : '';

    return `
      <div class="brain-investigation-panel">
        <!-- Header -->
        <div class="brain-panel-header">
          <div class="brain-panel-badge" style="background:${result.pattern?.color || '#6B7280'}22; border-color:${result.pattern?.color || '#6B7280'}44; color:${result.pattern?.color || '#9CA3AF'};">
            <span>${result.pattern?.icon || '🔍'}</span>
            <span>${result.pattern?.name || 'Investigation'}</span>
          </div>
          <div class="brain-confidence-badge" style="color:${conf.color}; background:${conf.color}22; border-color:${conf.color}44;">
            ${conf.icon} ${result.confidence}% Confidence — ${conf.label}
          </div>
        </div>

        <!-- Root Cause -->
        <div class="brain-section">
          <div class="brain-section-title">🎯 Root Cause</div>
          <div class="brain-rootcause-text">
            ${result.investigation?.rootCause || result.brainRootCause || 'Investigating...'}
          </div>
        </div>

        <!-- Evidence -->
        ${evidenceHTML ? `<div class="brain-section">
          <div class="brain-section-title">🔍 Evidence</div>
          <div class="brain-evidence-list">${evidenceHTML}</div>
        </div>` : ''}

        <!-- Timeline -->
        ${timelineHTML ? `<div class="brain-section">
          <div class="brain-section-title">⏱ API Execution Timeline</div>
          <div class="brain-timeline-list">${timelineHTML}</div>
        </div>` : ''}

        <!-- Possible Causes -->
        ${causesHTML ? `<div class="brain-section">
          <div class="brain-section-title">🔎 Possible Causes</div>
          <ul class="brain-causes-list">${causesHTML}</ul>
        </div>` : ''}

        <!-- Recommendations -->
        ${recsHTML ? `<div class="brain-section">
          <div class="brain-section-title">💡 Recommended Actions</div>
          <div class="brain-rec-list">${recsHTML}</div>
        </div>` : ''}

        <!-- Logger Suggestion -->
        ${loggerHTML}

        <!-- Confidence Boost -->
        ${boostHTML}

        <!-- Next Steps -->
        ${result.investigation?.nextSteps || result.nextSteps ? `<div class="brain-section">
          <div class="brain-section-title">📌 Next Steps</div>
          <div class="brain-nextsteps">${escHtml ? escHtml(result.investigation?.nextSteps || result.nextSteps) : (result.investigation?.nextSteps || result.nextSteps)}</div>
        </div>` : ''}

        <div class="brain-footer">LogRadar Intelligence v${LOGRADAR_BRAIN.version} — Senior L3 Methodology</div>
      </div>`;
  },

  // Render a compact brain summary card for the root cause drawer
  renderBrainDrawerCard(rowResult) {
    if (!rowResult || !rowResult.pattern) return '';
    const conf = CONFIDENCE_ENGINE.getLabel(rowResult.confidence);

    const recsHTML = (rowResult.recommendations || []).slice(0, 3).map(r =>
      `<div class="brain-mini-rec">
        <span class="brain-mini-priority brain-priority-${(r.priority || 'MEDIUM').toLowerCase()}">${r.priority}</span>
        <span>${escHtml ? escHtml(r.action) : r.action}</span>
       </div>`
    ).join('');

    const boostActions = CONFIDENCE_ENGINE.getBoostActions(rowResult.confidence, rowResult);
    const boostHTML = boostActions.length ? `
      <div style="margin-top:12px; padding:10px; background:rgba(239, 68, 68, 0.04); border:1px dashed rgba(239, 68, 68, 0.25); border-radius:6px; font-size:11px; color:var(--text-normal);">
        <div style="color:#EF4444; font-weight:700; margin-bottom:4px; font-size:11.5px; display:flex; align-items:center; gap:4px;"><span>⚠️</span> Missing Evidence / Telemetry Recommendations</div>
        <ul style="margin:0; padding-left:14px; display:flex; flex-direction:column; gap:4px;">
          ${boostActions.map(a => `<li>${escHtml ? escHtml(a) : a}</li>`).join('')}
        </ul>
      </div>` : '';

    return `
      <div class="brain-drawer-card">
        <div class="brain-drawer-header">
          <span class="brain-drawer-icon">${rowResult.pattern.icon || '🧠'}</span>
          <span class="brain-drawer-title">Brain: ${rowResult.pattern.name}</span>
          <span class="brain-drawer-conf" style="color:${conf.color}">${conf.icon} ${rowResult.confidence}%</span>
        </div>
        ${rowResult.brainRootCause ? `<div class="brain-drawer-cause">${escHtml ? escHtml(rowResult.brainRootCause) : rowResult.brainRootCause}</div>` : ''}
        ${recsHTML ? `<div class="brain-drawer-recs">${recsHTML}</div>` : ''}
        ${rowResult.nextSteps ? `<div class="brain-drawer-nextstep">→ ${escHtml ? escHtml(rowResult.nextSteps) : rowResult.nextSteps}</div>` : ''}
        ${boostHTML}
      </div>`;
  },
};

// Expose globally
window.LOGRADAR_BRAIN = LOGRADAR_BRAIN;
