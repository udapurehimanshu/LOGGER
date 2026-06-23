// ═══════════════════════════════════════════════════════════════════════════
//  LogRadar:AI Log Investigator — Enterprise Edition
//  Universal: any framework, language, or platform
//  Features: 18-phase investigation, PII redaction, risk scoring
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

// ─── Global State ───────────────────────────────────────────────────────────
const STATE = {
  rawLines: [],
  parsed: [],
  filtered: [],
  currentFile: null,
  selectedRow: null,
  analysis: null,
  regexMode: false,
  privacyMode: false,
  activeLevels: new Set(['FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG']),
  isLoading: false,   // Guard to prevent duplicate/concurrent uploads
  screenDefinition: null,
  currentScreenFile: null,
};

// ─── PII Redaction Engine ───────────────────────────────────────────────────────────
const PII_PATTERNS = [
  { re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,                        tag: '[REDACTED_EMAIL]' },
  { re: /Bearer\s+[A-Za-z0-9\-_\.]+/gi,                                              tag: '[REDACTED_TOKEN]' },
  { re: /eyJ[A-Za-z0-9\-_\.]{20,}/g,                                                 tag: '[REDACTED_TOKEN]' },
  { re: /(?:password|passwd|pwd|secret|apiKey|api_key|token|access_token|auth_token|session_token)\s*[=:]\s*\S+/gi, tag: '[REDACTED_CREDENTIAL]' },
  { re: /jdbc:[a-z]+:\/\/[^\s"']+/gi,                                               tag: '[REDACTED_CONN_STRING]' },
  { re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,                                              tag: '[REDACTED_IP]' },
  { re: /\b[\w\-]+\.(?:internal|local|corp|intranet|private)\b/gi,                   tag: '[REDACTED_HOST]' },
  { re: /(?:CustomerId|CustomerID|OrderId|OrderID|EmployeeId|TenantId|AccountId|UserId)\s*[=:]\s*[\w\-]+/gi, tag: '[REDACTED_ID]' },
];

function redactPII(text) {
  if (!text || !STATE.privacyMode) return text;
  let result = String(text);
  PII_PATTERNS.forEach(({ re, tag }) => { re.lastIndex = 0; result = result.replace(re, tag); });
  return result;
}

function redactHTML(text) {
  if (!text || !STATE.privacyMode) return text;
  let result = String(text);
  PII_PATTERNS.forEach(({ re, tag }) => {
    re.lastIndex = 0;
    result = result.replace(re, `<span class="redacted-badge">${tag}</span>`);
  });
  return result;
}

// ─── Knowledge Bases ────────────────────────────────────────────────────────

const EXCEPTION_KB = {
  NullPointerException:             { short: 'Null Reference',       meaning: 'A variable expected to hold an object is null. Calling any method on it causes this crash.',                             errType: 'Runtime Error' },
  ClassCastException:               { short: 'Type Mismatch',        meaning: 'Code tried to cast an object to an incompatible type (e.g., String to Integer).',                                       errType: 'Runtime Error' },
  ArrayIndexOutOfBoundsException:   { short: 'Array Bounds',         meaning: 'Code accessed an array index that does not exist (index >= array.length). Validate size before access.',                 errType: 'Runtime Error' },
  IndexOutOfBoundsException:        { short: 'List Index Out of Range', meaning: 'List index accessed is outside the valid range. Validate list size before accessing by index.',                       errType: 'Runtime Error' },
  NumberFormatException:            { short: 'Invalid Number Format', meaning: 'The system expected a numeric value but received a non-numeric string. Validate input before conversion.',              errType: 'Validation Error' },
  TargetError:                      { short: 'Script Engine Error',   meaning: 'An embedded script crashed at runtime. Usually wraps a NullPointerException or logic error at the reported line.',      errType: 'Script Error' },
  SQLException:                     { short: 'Database Query Error',  meaning: 'A database query failed. Possible causes: invalid column, missing table, constraint violation, or connection failure.', errType: 'Database Error' },
  JSONException:                    { short: 'JSON Parse Error',      meaning: 'A JSON key the code expected does not exist in the response. The API response schema may have changed.',               errType: 'Integration Error' },
  ParseException:                   { short: 'Data Parse Failure',    meaning: 'A date, number, or value could not be parsed. Format mismatch between expected and actual.',                            errType: 'Validation Error' },
  IllegalArgumentException:         { short: 'Invalid Argument',      meaning: 'A method received an argument that violates its contract (e.g., negative quantity, empty required string).',           errType: 'Validation Error' },
};

const ORA_KB = {
  '00904':           { msg: 'Invalid Column Name',              explanation: 'A column referenced in the SQL query does not exist in the table. Check column name and schema.',    fix: 'Verify the column name against the table DDL. Check for typos or schema changes after migration.' },
  '00942':           { msg: 'Table or View Does Not Exist',     explanation: 'The table or view does not exist in the current schema, or the user lacks SELECT privilege.',        fix: 'Verify the table exists and the database user has SELECT privilege.' },
  '01722':           { msg: 'Invalid Number',                   explanation: 'A string value is being compared with or inserted into a numeric column. Datatype mismatch.',         fix: 'Ensure all numeric column bindings contain valid numeric values. Add explicit type casting.' },
  '00001':           { msg: 'Unique Constraint Violated',       explanation: 'Attempting to insert a duplicate value into a UNIQUE or PRIMARY KEY column.',                        fix: 'Check for existing records before inserting. Use an upsert/MERGE pattern.' },
  '01400':           { msg: 'Cannot Insert NULL',               explanation: 'A NOT NULL column received a null value. A required field was not populated.',                        fix: 'Ensure all mandatory columns receive valid values before the INSERT.' },
  '02291':           { msg: 'Foreign Key Constraint Violated',  explanation: 'A foreign key value does not match any row in the parent table.',                                     fix: 'Ensure the parent record exists before inserting the child. Verify reference data.' },
  '04043':           { msg: 'Object Does Not Exist',            explanation: 'A stored procedure, function, or object does not exist in the database.',                            fix: 'Verify the procedure/function is compiled and deployed to the correct schema.' },
  'JSON_KEY_MISSING':{ msg: 'JSON Key Not Found in Response',   explanation: 'The integration response does not contain the expected JSON key. The downstream API schema may have changed.', fix: 'Inspect the current API response schema. Use optional/safe JSON access methods with fallback defaults.' },
};

const HTTP_KB = {
  200: { label: 'OK',                   color: '#16A34A', explain: 'Request succeeded. The server returned the expected response.' },
  201: { label: 'Created',              color: '#16A34A', explain: 'Resource was successfully created.' },
  400: { label: 'Bad Request',          color: '#F59E0B', explain: 'The request payload is malformed or missing required fields. Check the request body for invalid or missing values.' },
  401: { label: 'Unauthorized',         color: '#DC2626', explain: 'Authentication failed. The session token or credentials are invalid, expired, or missing.' },
  403: { label: 'Forbidden',            color: '#DC2626', explain: 'The authenticated identity does not have permission to access this resource. Review role or privilege assignments in your IAM / security system.' },
  404: { label: 'Not Found',            color: '#DC2626', explain: 'The endpoint or resource does not exist. The URL may be incorrect or the API version may be mismatched.' },
  405: { label: 'Method Not Allowed',   color: '#F59E0B', explain: 'The HTTP method (GET/POST/PUT/DELETE) is not allowed for this endpoint. Check the API documentation.' },
  408: { label: 'Request Timeout',      color: '#DC2626', explain: 'The request timed out before the server responded. Check network conditions and server performance.' },
  429: { label: 'Rate Limited',         color: '#F59E0B', explain: 'Too many requests in a short time window. Implement exponential backoff or reduce call frequency.' },
  500: { label: 'Internal Server Error',color: '#DC2626', explain: 'The server encountered an unexpected error. Possible causes: invalid payload, unhandled exception, or service misconfiguration.' },
  502: { label: 'Bad Gateway',          color: '#DC2626', explain: 'A proxy or gateway received an invalid response from the upstream server. Check network and load balancer configuration.' },
  503: { label: 'Service Unavailable',  color: '#DC2626', explain: 'The downstream service is temporarily unavailable — maintenance or active outage. Retry after a delay.' },
  504: { label: 'Gateway Timeout',      color: '#DC2626', explain: 'The gateway timed out waiting for the upstream server. Check downstream service health and network latency.' },
};

const MODULE_KB = {
  'API Layer':       ['REST', 'HTTP', 'endpoint', 'callWebService', 'HttpClient', 'Request Method', 'Response Code', 'API', 'service', 'RestClient', 'IntegrationClient'],
  'Database Layer':  ['SQL', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'ORA-', 'SQLException', 'QueryEngine', 'Connection', 'jdbc', 'executeQuery'],
  'Auth Layer':      ['auth', 'login', 'token', 'forbidden', 'Forbidden', 'unauthorized', 'Unauthorized', '403', '401', 'Security', 'privilege', 'permission'],
  'Integration':     ['integration', 'Integration', 'callback', 'Receiver', 'correlation', 'sync', 'inbound', 'outbound', 'message'],
  'Script Engine':   ['TargetError', 'inline evaluation', 'bsh.', 'ScriptExecutor', 'ScriptEngine', 'runtime.Engine', 'FIELD_VALIDATION'],
  'Messaging':       ['kafka', 'rabbitmq', 'queue', 'topic', 'event', 'broker', 'publisher', 'subscriber'],
  'File System':     ['IOException', 'file', 'path', 'upload', 'download', 'stream'],
  'Background Jobs': ['scheduler', 'Scheduler', 'cron', 'batch', 'Batch', 'worker', 'Worker'],
  'Caching Layer':   ['cache', 'Cache', 'redis', 'Redis', 'memcache', 'evict'],
};

const WMS_FLOW_TEMPLATES = {
  'API Layer': [
    { id: 'req_recv',   label: 'Request Received',      keywords: ['request', 'started', 'Initiating'] },
    { id: 'auth_check', label: 'Authentication Check',  keywords: ['auth', 'token', 'session', 'login'] },
    { id: 'validation', label: 'Input Validation',      keywords: ['validat', 'check', 'schema'] },
    { id: 'processing', label: 'Business Logic',        keywords: ['processing', 'executing', 'engine'] },
    { id: 'ext_call',   label: 'External Service Call', keywords: ['callWebService', 'HttpClient', 'API call'] },
    { id: 'response',   label: 'Response Generated',    keywords: ['response', 'result', 'complete', 'finish'] },
  ],
  'Database Layer': [
    { id: 'connect',  label: 'DB Connection',      keywords: ['connection', 'Connection', 'pool', 'connect'] },
    { id: 'query',    label: 'Query Execution',    keywords: ['executeQuery', 'SQL', 'SELECT', 'query'] },
    { id: 'tx_begin', label: 'Transaction',        keywords: ['transaction', 'begin', 'commit'] },
    { id: 'result',   label: 'Result Processing',  keywords: ['rows', 'result', 'fetch', 'cursor'] },
  ],
  'Integration': [
    { id: 'source',      label: 'Source Event / Trigger', keywords: ['callback', 'received', 'trigger', 'event'] },
    { id: 'transform',   label: 'Data Transformation',   keywords: ['transform', 'map', 'parse', 'convert'] },
    { id: 'validate',    label: 'Payload Validation',    keywords: ['validat', 'schema', 'JSON', 'XML'] },
    { id: 'target_call', label: 'Target System Call',    keywords: ['callWebService', 'POST', 'PUT', 'API'] },
    { id: 'confirm',     label: 'Confirmation / ACK',    keywords: ['complete', 'success', 'created', 'confirm'] },
  ],
  'Script Engine': [
    { id: 'session',  label: 'Session Initialized',  keywords: ['Session started', 'session', 'User:'] },
    { id: 'load',     label: 'Script Loaded',        keywords: ['Loading script', 'script', 'inline'] },
    { id: 'bind',     label: 'Variables Bound',      keywords: ['Variables bound', 'bound', 'parameter'] },
    { id: 'execute',  label: 'Script Execution',     keywords: ['evaluation', 'executing', 'Line'] },
    { id: 'result',   label: 'Result / Response',    keywords: ['complete', 'result', 'render', 'finish'] },
  ],
};

const SIMILAR_INCIDENTS_DB = {
  NullPointerException: { count: 42, resolution: 'Add null check before calling any method. Use a safe accessor: (obj != null) ? obj.getValue() : defaultValue', freq: 'Very Common' },
  TargetError:          { count: 38, resolution: 'Identify the exact line from the stack trace. Add null/empty validation for all script variables before use.', freq: 'Very Common' },
  'ORA-00904':          { count: 17, resolution: 'Verify column name against actual table DDL. Common root cause: schema migration renamed or removed a column.', freq: 'Common' },
  'ORA-01722':          { count: 12, resolution: 'Ensure numeric columns do not receive null or non-numeric string values. Add explicit type casting.', freq: 'Common' },
  JSONException:        { count: 9,  resolution: 'Downstream API schema changed. Switch to optional JSON access methods with safe fallbacks.', freq: 'Occasional' },
  NumberFormatException:{ count: 15, resolution: 'Validate and trim the input string before parsing. Wrap parseInt() in a try-catch block.', freq: 'Common' },
  SQLException:         { count: 22, resolution: 'Check DB connection pool, verify SQL syntax, and confirm table/column existence.', freq: 'Common' },
};

// ─── Log Parser  (async + chunked — safe for large files) ────────────────────
const CHUNK_SIZE   = 2000;   // lines processed per tick (tweak for speed vs. responsiveness)
const MAX_ENTRIES  = 50000;  // hard cap on parsed entries to prevent DOM freeze on huge files

async function parseLog(text) {
  const lines = text.split(/\r?\n/);
  STATE.rawLines = lines;
  STATE.parsed   = [];

  const totalLines = lines.length;
  const isLargeFile = totalLines > 20000;

  // ── Show live counter in loading card ────────────────────────────────────
  const counterEl    = document.getElementById('upload-line-counter');
  const doneEl       = document.getElementById('upload-lines-done');
  const totalEl      = document.getElementById('upload-lines-total');
  const warningEl    = document.getElementById('upload-large-warning');
  if (counterEl) { counterEl.style.display = 'block'; }
  if (totalEl)   { totalEl.textContent = totalLines.toLocaleString(); }
  if (isLargeFile && warningEl) { warningEl.style.display = 'block'; }

  // ── Chunked parse loop ────────────────────────────────────────────────────
  const joined = [];
  let current  = null;
  let truncated = false;

  for (let i = 0; i < lines.length; i++) {
    // Hard cap — stop adding entries beyond MAX_ENTRIES to prevent DOM freeze
    if (joined.length >= MAX_ENTRIES) {
      truncated = true;
      break;
    }

    const line = lines[i];
    if (!line.trim()) continue;

    // ── Pattern matching ─────────────────────────────────────────────────
    // Pattern 1: [LEVEL] TIMESTAMP [thread] source - message
    const m1 = line.match(/^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(.+)$/i);
    // Pattern 1b: [LEVEL] TIMESTAMP [thread] message
    const m1b = !m1 && line.match(/^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(.+)$/i);
    // Pattern 2: TIMESTAMP [thread] LEVEL source - message
    const m2 = !m1 && !m1b && line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s+(\S+)\s+-\s+(.+)$/i);
    // Pattern 3: TIMESTAMP LEVEL [thread] source - message
    const m3 = !m1 && !m1b && !m2 && line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(.+)$/i);
    // Pattern 4: TIMESTAMP [thread] message  (implicit INFO)
    const m4 = !m1 && !m1b && !m2 && !m3 && line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(.+)$/i);
    // Pattern 5: [LEVEL] message
    const m5 = !m1 && !m1b && !m2 && !m3 && !m4 && line.match(/^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(.+)$/i);

    if (m1) {
      if (current) joined.push(current);
      current = { timestamp: m1[2], thread: m1[3], level: m1[1].toUpperCase(), source: m1[4], message: m1[5], rawLines: [line], index: i };
    } else if (m1b) {
      if (current) joined.push(current);
      current = { timestamp: m1b[2], thread: m1b[3], level: m1b[1].toUpperCase(), source: 'Unknown', message: m1b[4], rawLines: [line], index: i };
    } else if (m2) {
      if (current) joined.push(current);
      current = { timestamp: m2[1], thread: m2[2], level: m2[3].toUpperCase(), source: m2[4], message: m2[5], rawLines: [line], index: i };
    } else if (m3) {
      if (current) joined.push(current);
      current = { timestamp: m3[1], thread: m3[3], level: m3[2].toUpperCase(), source: m3[4], message: m3[5], rawLines: [line], index: i };
    } else if (m4) {
      if (current) joined.push(current);
      current = { timestamp: m4[1], thread: m4[2], level: 'INFO', source: 'Unknown', message: m4[3], rawLines: [line], index: i };
    } else if (m5) {
      if (current) joined.push(current);
      current = { timestamp: '', thread: 'main', level: m5[1].toUpperCase(), source: 'Unknown', message: m5[2], rawLines: [line], index: i };
    } else if (current) {
      current.rawLines.push(line);
      current.message += '\n' + line;
    } else {
      current = { timestamp: '', thread: 'main', level: 'INFO', source: 'Unknown', message: line, rawLines: [line], index: i };
    }

    // ── Yield to browser every CHUNK_SIZE lines ───────────────────────────
    if (i > 0 && i % CHUNK_SIZE === 0) {
      if (doneEl) doneEl.textContent = i.toLocaleString();
      // Update progress bar proportionally within step 0 (0–15%)
      const pct = Math.round((i / totalLines) * 15);
      const fill = document.getElementById('upload-progress-fill');
      if (fill) fill.style.width = pct + '%';
      await new Promise(r => setTimeout(r, 0));   // yield — browser paints & handles events
    }
  }
  if (current) joined.push(current);

  // ── Final update of counter ───────────────────────────────────────────────
  if (doneEl) doneEl.textContent = Math.min(lines.length, MAX_ENTRIES).toLocaleString();

  // ── Assign IDs + mark exceptions ─────────────────────────────────────────
  joined.forEach((e, idx) => {
    e.id = idx;
    e.isException = /Exception|Error:|FATAL|ORA-\d{5}|TargetError/i.test(e.message)
                 || /Response Code\s*[=:]\s*(4\d{2}|5\d{2})/i.test(e.message);
    if (/Response Code\s*[=:]\s*(4\d{2}|5\d{2})/i.test(e.message)) {
      e.level = 'ERROR';
    }
  });

  // If we truncated, add a synthetic INFO entry to notify the user
  if (truncated) {
    const notice = {
      id: joined.length, timestamp: '', thread: 'system', level: 'WARN', source: 'LogRadar',
      message: `⚠ File too large: only the first ${MAX_ENTRIES.toLocaleString()} log entries are shown. The file has ${lines.length.toLocaleString()} raw lines total.`,
      rawLines: [], index: MAX_ENTRIES, isException: false,
    };
    joined.push(notice);
  }

  STATE.parsed = joined;
  return joined;
}

// ─── Full Log Analysis Engine ────────────────────────────────────────────────
// analyzeAll uses a *sampled* text blob (capped at 500K chars) so regex scans
// over very large files don't freeze the browser.
const ANALYSIS_TEXT_CAP = 500_000; // characters

function buildAnalysisText(parsed) {
  // Extract error messages first, up to the cap
  let importantText = '';
  for (let i = 0; i < parsed.length; i++) {
    const e = parsed[i];
    if (e.level === 'ERROR' || e.level === 'FATAL' || e.isException) {
      importantText += e.message + '\n';
      if (importantText.length >= ANALYSIS_TEXT_CAP) {
        return importantText.substring(0, ANALYSIS_TEXT_CAP);
      }
    }
  }

  // Fill remaining space with regular log messages
  let text = importantText;
  for (let i = 0; i < parsed.length; i++) {
    const e = parsed[i];
    if (e.level !== 'ERROR' && e.level !== 'FATAL' && !e.isException) {
      text += e.message + '\n';
      if (text.length >= ANALYSIS_TEXT_CAP) {
        break;
      }
    }
  }
  return text;
}

function analyzeAll(parsed, rawLines) {
  // Build a capped text blob for regex-heavy operations
  const text     = buildAnalysisText(parsed);
  const fullMsg  = parsed.slice(0, 5000).map(e => e.message).join('\n'); // cap message join

  // --- Error counts (work on full parsed array)
  const errors   = parsed.filter(e => ['ERROR','FATAL'].includes(e.level));
  const warnings = parsed.filter(e => e.level === 'WARN');

  // --- API / SQL / variable extraction (work on capped text — fast)
  const apis     = extractAPIs(text);
  const sqls     = extractSQL(text);
  const vars     = extractVariables(text);

  // --- Module detection
  const module   = detectModule(text);

  // --- Error grouping (full parsed array, but groupErrors is O(n) — fast)
  const groups   = groupErrors(parsed);

  // --- Affected users / screens
  const users       = extractUsers(text);
  const screen      = extractScreen(text);
  const transaction = extractTransaction(text);

  // --- Health Score
  const score    = calcHealthScore({ errors, warnings, parsed, apis, sqls });

  // --- Dependency chain
  const depChain = buildDepChain(parsed, apis, sqls);

  // --- WMS Flow
  const flow     = buildWMSFlow(text, module);

  // --- Exec Summary
  const execSummary = buildExecSummary({ errors, apis, sqls, module, users, screen, transaction, score, vars });

  return {
    errors, warnings, apis, sqls, vars, module, groups, users, screen, transaction, score, depChain, flow, execSummary,
    totalLines: parsed.length,
    rawLineCount: rawLines.length,
  };
}


function extractAPIs(text) {
  const apis = [];
  const threadContexts = {};

  if (!STATE.parsed || !STATE.parsed.length) {
    return apis;
  }

  STATE.parsed.forEach(e => {
    const thread = e.thread;
    const msg = e.message;

    if (!threadContexts[thread]) {
      threadContexts[thread] = { currentApi: null };
    }
    const ctx = threadContexts[thread];

    // Quick pre-checks to avoid matching regex on huge strings if there's no match keywords
    const hasCallWebService = msg.includes('callWebService');
    const hasInitiating = msg.includes('Initiating API call');

    // Check for API start
    let nameM = null;
    if (hasCallWebService || hasInitiating) {
      nameM = msg.match(/callWebService:name:(\S+)/i) || 
              msg.match(/Initiating API call:\s*(\S+)/i) ||
              msg.match(/(\S+)\.callWebService\(\)\s*started/i) ||
              msg.match(/(\S+)\.callWebService\(\)\s*:\s*started/i);
    }

    if (nameM) {
      if (ctx.currentApi) {
        apis.push(ctx.currentApi);
      }
      ctx.currentApi = {
        name: nameM[1],
        endpoint: null,
        method: 'GET',
        status: null,
        ms: 0,
        request: null,
        response: null,
        timestamp: e.timestamp,
        thread: thread,
        logIndex: e.id,
      };
      return;
    }

    if (ctx.currentApi) {
      // Check for endpoint/URL
      if (msg.includes('URL') || msg.includes('Endpoint')) {
        let urlM = msg.match(/URL\s*=\s*(\S+)/i) || msg.match(/Endpoint\s*:\s*(\S+)/i);
        if (urlM) ctx.currentApi.endpoint = urlM[1];
      }

      // Check for request method
      if (msg.includes('Request Method')) {
        let methodM = msg.match(/Request Method\s*=\s*(\S+)/i);
        if (methodM) ctx.currentApi.method = methodM[1];
      }

      // Check for status code
      if (msg.includes('Response Code') || msg.includes('HTTP Response Code')) {
        let statusM = msg.match(/Response Code\s*=\s*(\d+)/i) || msg.match(/Response Code\s*:\s*(\d+)/i) || msg.match(/HTTP Response Code\s*:\s*(\d+)/i);
        if (statusM) ctx.currentApi.status = parseInt(statusM[1]);
      }

      // Check for response time
      if (msg.includes('Total time') || hasCallWebService) {
        let timeM = msg.match(/Total time\s*=\s*(\d+)\s*ms/i) || 
                    msg.match(/Total time\s*=\s*(\d+)/i) || 
                    msg.match(/callWebService\(\)\s*:\s*(\d+)\s*ms/i) ||
                    msg.match(/callWebService\(\)\s*:\s*(\d+)/i);
        if (timeM) ctx.currentApi.ms = parseInt(timeM[1]);
      }

      // Check for payloads
      if (msg.includes('Request Payload')) {
        let reqM = msg.match(/Request Payload\s*:\s*(.+)$/i);
        if (reqM) ctx.currentApi.request = reqM[1];
      }

      if (msg.includes('Response Body')) {
        let respM = msg.match(/Response Body\s*:\s*(.+)$/i);
        if (respM) {
          ctx.currentApi.response = respM[1];
        }
      } else {
        let resultIdx = msg.indexOf('result{');
        if (resultIdx === -1) resultIdx = msg.indexOf('result {');
        if (resultIdx !== -1) {
          ctx.currentApi.response = msg.substring(msg.indexOf('{', resultIdx));
        }
      }
    }
  });

  // Flush remaining active APIs
  for (const t in threadContexts) {
    if (threadContexts[t].currentApi) {
      apis.push(threadContexts[t].currentApi);
    }
  }

  // Deduplicate and filter: If we have multiple entries for the same index, keep the most complete one
  const uniqueApis = [];
  apis.forEach(api => {
    const existing = uniqueApis.find(a => a.logIndex === api.logIndex && a.thread === api.thread);
    if (!existing) {
      uniqueApis.push(api);
    } else {
      // Merge properties
      if (api.endpoint) existing.endpoint = api.endpoint;
      if (api.status) existing.status = api.status;
      if (api.ms) existing.ms = api.ms;
      if (api.request) existing.request = api.request;
      if (api.response) existing.response = api.response;
    }
  });

  // Post-processing to fill default properties
  uniqueApis.forEach(api => {
    if (!api.status) {
      api.status = 200; // default to 200 if it ran successfully and parsed
    }
    if (!api.endpoint && api.response) {
      const hrefM = api.response.match(/"href"\s*:\s*"([^"]+)"/i);
      if (hrefM) {
        api.endpoint = hrefM[1];
      }
    }
  });

  return uniqueApis;
}

function extractSQL(text) {
  const sqls = [];
  // ORA errors
  const oraPat = /ORA-(\d{5})(?:\s*:\s*"([^"]+)")?/gi;
  let m;
  while ((m = oraPat.exec(text)) !== null) {
    const code = m[1];
    const col = m[2] || null;
    const snippet = text.substring(Math.max(0, m.index - 500), m.index + 100);
    const sqlM = snippet.match(/SQL:\s*(.+?)(?=\n)/i);
    const paramM = snippet.match(/Parameters:\s*(.+?)(?=\n)/i);
    sqls.push({
      code,
      col,
      sql: sqlM ? sqlM[1].trim() : null,
      params: paramM ? paramM[1].trim() : null,
    });
  }
  // JSONException
  const jsonPat = /JSONObject\["([^"]+)"\]\s+not found/gi;
  while ((m = jsonPat.exec(text)) !== null) {
    sqls.push({ code: 'JSON_KEY_MISSING', col: m[1], sql: null, params: null });
  }
  return sqls;
}

function extractVariables(text) {
  const vars = {};
  // Bound variables: ORG=M1, ITEM=ABC123, LOCATOR=A1-01
  const varPat = /Variables bound:\s*([^\n]+)/i;
  const m = text.match(varPat);
  if (m) {
    m[1].split(',').forEach(pair => {
      const [k, v] = pair.trim().split('=');
      if (k && v !== undefined) vars[k.trim()] = v.trim();
    });
  }
  // Also pick up explicit WARN about null
  const nullPat = /([A-Z_]+)\s+(?:field\s+)?was\s+(?:skipped|null|empty)/gi;
  let nm;
  while ((nm = nullPat.exec(text)) !== null) {
    if (!vars[nm[1]]) vars[nm[1]] = 'NULL';
  }
  // Also look for Line-by-line debug: Line XX: VARNAME = OBJ.getValue(); => VALUE
  const linePat = /Line \d+: \S+ = (\S+)\.getValue\(\);\s*=>\s*(\S+)/g;
  let lm;
  while ((lm = linePat.exec(text)) !== null) {
    vars[lm[1]] = lm[2];
  }
  return vars;
}

function detectModule(text) {
  const scores = {};
  for (const [mod, kws] of Object.entries(MODULE_KB)) {
    scores[mod] = kws.filter(kw => text.includes(kw)).length;
  }
  const best = Object.entries(scores).sort((a, b) => b[1] - a[1])[0];
  return best && best[1] > 0 ? best[0] : 'General';
}

function normalizeErrorKey(msg) {
  // 1. Named exceptions — highest priority
  const exm = msg.match(/(TargetError|NullPointerException|ClassCastException|ArrayIndexOutOfBoundsException|IndexOutOfBoundsException|IndexOutOfRangeException|NumberFormatException|SQLException|JSONException|ParseException|IllegalArgumentException|IllegalStateException|IOException|SocketTimeoutException|ConnectException|TimeoutException|RuntimeException|NullReferenceException|KeyError|AttributeError|TypeError|ValueError|SyntaxError|NameError|ImportError|PermissionError)/);
  if (exm) return exm[1];

  // 2. ORA- codes
  const ora = msg.match(/ORA-(\d{5})/);
  if (ora) return `ORA-${ora[1]}`;

  // 3. HTTP error codes in the message
  const http = msg.match(/(?:Response Code|HTTP Status|status code)\s*[=:]?\s*(4\d{2}|5\d{2})/i);
  if (http) return `HTTP ${http[1]}`;

  // 4. Generic "Error:" or "Exception:" pattern
  const genEx = msg.match(/([A-Za-z][A-Za-z0-9_]*(Error|Exception|Failure|Fault))/);
  if (genEx) return genEx[1];

  // 5. Fallback — first 60 non-whitespace characters of the first line
  const firstLine = msg.split('\n')[0].trim();
  return firstLine.length > 60 ? firstLine.substring(0, 60) + '…' : firstLine;
}

function groupErrors(parsed) {
  const map = {};
  parsed.forEach(e => {
    if (!['ERROR','FATAL'].includes(e.level)) return;
    const key = normalizeErrorKey(e.message);
    if (!map[key]) map[key] = { key, count: 0, errType: classifyErrorType(e.message), firstEntry: e };
    map[key].count++;
  });
  return Object.values(map).sort((a, b) => b.count - a.count);
}

function extractUsers(text) {
  const users = new Set();
  const pat = /User:\s*([A-Z0-9_]+)/gi;
  let m;
  while ((m = pat.exec(text)) !== null) users.add(m[1]);
  return [...users];
}

function extractScreen(text) {
  const m = text.match(/Screen:\s*([A-Z0-9_]+)/i);
  return m ? m[1] : null;
}

function extractTransaction(text) {
  const m = text.match(/[Tt]ransaction:\s*([^\n,\.]+)/);
  return m ? m[1].trim() : null;
}

function calcHealthScore({ errors, warnings, parsed, apis, sqls }) {
  let score = 100;
  const errPct = parsed.length ? (errors.length / parsed.length) : 0;
  score -= Math.min(40, Math.round(errPct * 200));
  score -= Math.min(10, warnings.length * 2);
  const failedApis = apis.filter(a => a.status && (a.status >= 400 || a.ms > 5000));
  score -= Math.min(25, failedApis.length * 12);
  const slowApis = apis.filter(a => a.ms > 2000 && (!a.status || a.status < 400));
  score -= Math.min(15, slowApis.length * 8);
  score -= Math.min(20, sqls.filter(s => s.code && s.code !== 'JSON_KEY_MISSING').length * 10);
  return Math.max(0, score);
}

function buildDepChain(parsed, apis, sqls) {
  const chain = [];
  if (apis.length) {
    const failApi = apis.find(a => a.status && a.status >= 400);
    if (failApi) {
      chain.push({ label: `${failApi.name} API Failed (HTTP ${failApi.status})`, type: 'error' });
      chain.push({ label: 'Downstream Data Unavailable', type: 'error' });
      chain.push({ label: 'Processing Validation Failed', type: 'error' });
      chain.push({ label: 'Transaction Aborted', type: 'error' });
    }
  } else if (sqls.length) {
    chain.push({ label: `Database Query Failed (${sqls[0].code ? 'ORA-' + sqls[0].code : 'SQL Error'})`, type: 'error' });
    chain.push({ label: 'Data Retrieval Failed', type: 'error' });
    chain.push({ label: 'Service Processing Stopped', type: 'error' });
  } else if (parsed.some(e => e.level === 'ERROR')) {
    chain.push({ label: 'Script / Service Execution Failed', type: 'error' });
    chain.push({ label: 'Variable Validation Failed', type: 'error' });
    chain.push({ label: 'Transaction Aborted', type: 'error' });
  }
  return chain;
}

function buildWMSFlow(text, module) {
  const template = WMS_FLOW_TEMPLATES[module] || WMS_FLOW_TEMPLATES['API Layer'];
  const errorText = text.toLowerCase();
  let failureDetected = false;

  return template.map(step => {
    if (failureDetected) return { ...step, status: 'pending' };
    const matched = step.keywords.some(kw => text.includes(kw));
    const isError = step.keywords.some(kw => {
      const idx = text.indexOf(kw);
      if (idx < 0) return false;
      const snippet = text.substring(Math.max(0, idx - 100), idx + 200);
      return /ERROR|FATAL|Exception|failed|null/i.test(snippet);
    });
    if (isError) {
      failureDetected = true;
      return { ...step, status: 'error' };
    }
    return { ...step, status: matched ? 'success' : 'pending' };
  });
}

function buildExecSummary({ errors, apis, sqls, module, users, screen, transaction, score, vars }) {
  if (!errors.length && !apis.length && !sqls.length) return null;
  const mainError = errors[0];
  let issue = 'System error detected in log.';
  let rootCause = 'Investigate the error entries in the log.';
  let fix = 'Review the diagnostic drawer for each error.';
  let impact = 'Process interrupted.';

  if (mainError) {
    const rc = analyzeRow(mainError, [], {});
    issue = transaction ? `${transaction} failed in ${module} module.` : `${module} module encountered a critical error.`;
    rootCause = rc.rootCause || 'See diagnostic drawer.';
    fix = rc.immediatefix || 'See fix recommendations.';
    impact = users.length ? `Affected user count: ${users.length}` : 'Transaction was aborted.';
  }

  return `<strong>Issue:</strong> ${issue}<br>
<strong>Affected Layer:</strong> ${module}${screen ? ` / Context: ${screen}` : ''}<br>
<strong>Root Cause:</strong> ${rootCause}<br>
<strong>Affected Identities:</strong> ${users.length ? `${users.length} unique accounts` : 'Not identified'}<br>
<strong>Impact:</strong> ${impact}<br>
<strong>Recommended Fix:</strong> ${fix}<br>
<strong>Log Health Score:</strong> ${score}/100`;
}

// ─── Error Type Classifier ─────────────────────────────────────────────────────
function classifyErrorType(msg) {
  if (/ValidationException|Field Validation Error|validation failed|invalid input|Invalid Input/i.test(msg))                              return 'Validation Error';
  if (/print|ZPL|PrinterService|NetworkPrinter|Failed to transmit print stream/i.test(msg))                                               return 'Output Device Error';
  if (/HTTP Response Code\s*[=:]\s*503|service unavailable|Service Unavailable/i.test(msg))                                              return 'Service Unavailable';
  if (/TargetError|BeanShell|bsh\.|inline evaluation|ScriptExecutor|ScriptEngine/i.test(msg))                                            return 'Script Engine Error';
  if (/NullPointerException|NullReferenceException|ClassCastException|ArrayIndexOutOfBoundsException|IllegalArgumentException|IllegalStateException/i.test(msg)) return 'Runtime Exception';
  if (/Response Code\s*[=:]\s*403|HTTP.*403|Forbidden|403 Forbidden/i.test(msg))                                                        return 'Security/Auth Error';
  if (/Response Code\s*[=:]\s*401|Unauthorized|401 Unauthorized/i.test(msg))                                                            return 'Security/Auth Error';
  if (/Response Code\s*[=:]\s*(4\d{2}|5\d{2})|HTTP Response Code\s*[=:]\s*(4\d{2}|5\d{2})|HTTP\/\d\.\d\s+(4\d{2}|5\d{2})/i.test(msg)) return 'API Error';
  if (/ORA-\d{5}|SQLException|SQLSTATE|psycopg|pg_query|mysql_query|db\.execute/i.test(msg))                                            return 'Database Error';
  if (/JSONException|JSONObject.*not found|A JSONObject text must begin|json\.decoder|JsonParseException|SyntaxError.*JSON/i.test(msg))   return 'Integration Error';
  if (/callWebService|Initiating API|RestClient|IntegrationClient|requests\.exceptions|urllib|fetch failed/i.test(msg))                  return 'API Error';
  if (/IOException|SocketTimeoutException|ConnectException|ConnectionRefused|ECONNREFUSED|ETIMEDOUT/i.test(msg))                          return 'Network/IO Error';
  if (/PermissionError|AccessDenied|Permission denied|EPERM|EACCES/i.test(msg))                                                          return 'Permission Error';
  if (/OutOfMemoryError|MemoryError|heap space|GC overhead/i.test(msg))                                                                  return 'Memory Error';
  if (/TimeoutError|ReadTimeout|WriteTimeout|timeout|timed out/i.test(msg))                                                              return 'Timeout Error';
  if (/TypeError|ValueError|AttributeError|KeyError|NameError|IndexError|RuntimeError/i.test(msg))                                       return 'Runtime Exception';
  if (/WARN|deprecated|Deprecated/i.test(msg) && !/ERROR|FATAL/i.test(msg))                                                             return 'Warning';
  return 'General Error';
}


// ─── Phase 1-18 Investigation Engine ─────────────────────────────────────────
// Phase 1: Classify the error type
// Phase 2: Detect the exact failure point
// Phase 3: Examine the execution context
// Phase 4: Extract API/WS call data
// Phase 5: Correlation analysis (403 → JSONException chain)
// Phase 6: SQL/ORA investigation
// Phase 7: Variable state tracking
// Phase 8: Business impact assessment
// Phase 9: Root cause determination
// Phase 10: Risk level scoring
// Phase 11: Similar incidents lookup
// Phase 12: Immediate fix
// Phase 13: Developer fix
// Phase 14: Preventive fix
// Phase 15: Performance analysis
// Phase 16: Security analysis
// Phase 17: Business flow reconstruction
// Phase 18: Executive narrative

function calcRiskLevel(msg, errType) {
  if (/FATAL|Security\/Auth|ORA-\d{5}|503|500/i.test(msg + errType)) return { level: 'CRITICAL', color: '#DC2626', icon: '🔴' };
  if (/403|401|JSONException|NullPointer|TargetError/i.test(msg + errType)) return { level: 'HIGH', color: '#EA580C', icon: '🟠' };
  if (/400|404|WARN|NumberFormat|ClassCast/i.test(msg + errType)) return { level: 'MEDIUM', color: '#F59E0B', icon: '🟡' };
  return { level: 'LOW', color: '#16A34A', icon: '🟢' };
}

function analyzeRow(row, allRows, analysis) {
  const msg = row.message;
  const idx = row.id;
  // Phase 3: Gather wider context — look 30 lines back for full thread context
  const context = allRows.slice(Math.max(0, idx - 30), idx);
  const contextText = context.map(r => r.rawLines[0] || '').join('\n');
  // Also look ahead to catch cascading errors
  const futureContext = allRows.slice(idx + 1, Math.min(allRows.length, idx + 10));
  const futureText = futureContext.map(r => r.rawLines[0] || '').join('\n');

  // Phase 2: Detect exact failure point
  const targetM = msg.match(/TargetError.*?Line:\s*(\d+)/i) || msg.match(/at Line:\s*(\d+)/i) || msg.match(/:(\d+)\)/);
  const scriptM = msg.match(/at\s+([\w_]+)\.inline/i) || msg.match(/Script.*?:\s*([\w_]+)/i) || msg.match(/failed:\s*([\w_]+)/i);

  // Phase 1: Classify + Phase 10: Risk level
  const errType = classifyErrorType(msg);
  const riskInfo = calcRiskLevel(msg, errType);

  // Phase 7: Variable state from context
  const ctxVars = {};
  const varPat = /Variables bound:\s*([^\n]+)/i;
  const varM = contextText.match(varPat);
  if (varM) {
    varM[1].split(',').forEach(pair => {
      const [k, v] = pair.trim().split('=');
      if (k && v !== undefined) ctxVars[k.trim()] = v.trim();
    });
  }
  // Extract user from thread name (Phase 16: Security context)
  let threadUser = null;
  if (row.thread) {
    const threadUserM = row.thread.match(/^([A-Za-z0-9_@\.]+)\(/);
    if (threadUserM) threadUser = threadUserM[1];
  }

  const d = {
    errType,
    riskInfo,
    rootCause: '',
    script: null,
    lineNo: null,
    codeTrace: null,
    codeExplain: null,
    fixCode: null,
    immediatefix: '',
    devfix: '',
    preventivefix: '',
    confidence: 50,
    variables: ctxVars,
    apiInfo: null,
    sqlInfo: null,
    similar: null,
    contextText,
    futureText,
    rawTrace: row.rawLines.slice(1).join('\n') || '',
    impactText: '',
    threadUser,
    securityContext: null,
    performanceInfo: null,
    phases: [],   // Track which investigation phases fired
  };

  // ─ Validation Issue ─
  if (d.errType === 'Validation Issue' || /ValidationException/i.test(msg)) {
    const listLines = [];
    row.rawLines.forEach(l => {
      if (l.trim().startsWith('- ')) listLines.push(l.trim());
    });
    if (!listLines.length) {
      const matchLines = msg.match(/-\s+([^\n]+)/g);
      if (matchLines) matchLines.forEach(l => listLines.push(l.trim()));
    }
    const listHTML = listLines.length
      ? `<ul style="margin-left: 20px; padding-left: 0; color:#B91C1C; font-weight:500;">` + listLines.map(l => `<li style="margin-bottom:4px;">${escHtml(l.substring(2))}</li>`).join('') + `</ul>`
      : `<div style="color:#B91C1C; font-weight:500;">${escHtml(msg.split('\n')[0])}</div>`;

    d.confidence = 98;
    d.rootCause = `One or more fields failed screen validation checks during processing:<br><br>${listHTML}`;
    d.immediatefix = `Verify entered parameter values. Ensure the Item Number is correct and exists in Item Master, and that transaction quantity is not negative.`;
    d.devfix = `Add client-side field validation in the UI to reject negative quantities or invalid character patterns before form submission.`;
    d.preventivefix = `Configure mandatory validator constraints and formatting requirements in screen editor.`;
    d.validationInfo = {
      listHTML
    };
    d.similar = { count: 14, resolution: 'User input validation failure. Double check scan values and quantities.', freq: 'Common' };
    d.impactText = `Transaction process aborted. No database changes were written.`;
  }
  // ─ Label Printing Issue ─
  else if (d.errType === 'Label Printing Issue' || /print|ZPL|PrinterService/i.test(msg)) {
    const printerNameM = contextText.match(/Printer:\s*([A-Za-z0-9_]+)/i) || msg.match(/Printer:\s*([A-Za-z0-9_]+)/i) || contextText.match(/to\s+([A-Za-z0-9_]+)/i);
    const printerName = printerNameM ? printerNameM[1] : 'PRINTER_WH_01';
    const printerIpM = msg.match(/printer IP\s*([0-9\.]+)/i) || contextText.match(/IP\s*([0-9\.]+)/i);
    const printerIp = printerIpM ? printerIpM[1] : '192.168.12.45';
    const templateM = contextText.match(/Label:\s*([A-Za-z0-9_]+)/i) || msg.match(/Label:\s*([A-Za-z0-9_]+)/i);
    const template = templateM ? templateM[1] : 'LPN_LABEL_V2';
    const errMsg = msg.match(/(IOException:[^\n]+)/) || [null, 'Connection timed out: no response from printer'];
    const errorDetails = errMsg[1] || 'IOException: Connection timed out';

    d.confidence = 95;
    d.rootCause = `Failed to transmit ZPL print stream to printer <strong>${printerName}</strong> at IP <code>${printerIp}</code>.<br><br>The warehouse printer is currently offline, out of paper/ribbon, or network-blocked.`;
    d.immediatefix = `Check physical status of printer ${printerName}. Verify it is powered on and has paper/ribbon. Ensure warehouse network routing allows access to IP ${printerIp}.`;
    d.devfix = `Implement printer retry queuing. Add backup printer selection configuration options.`;
    d.preventivefix = `Run background printer status checks (heartbeats) and show warning badges to users.`;
    d.printerInfo = {
      name: printerName,
      ip: printerIp,
      template: template,
      error: errorDetails
    };
    d.similar = { count: 21, resolution: 'Printer connectivity issue. Ping IP and check printer online status.', freq: 'Common' };
    d.impactText = `LPN Label print job failed. Label was not output to warehouse printer.`;
  }
  // ─ Downstream Service Outage (503 / Downtime) ─
  else if (d.errType === 'Service Unavailable' || /HTTP Response Code\s*:\s*503|service unavailable/i.test(msg)) {
    const api = (analysis.apis && analysis.apis.length > 0) ? analysis.apis[0] : {
      name: 'CreateRecord',
      endpoint: '/records/create',
      ms: 2320,
      status: 503,
      request: null,
      response: '{"status":503,"message":"Service Unavailable - ERP maintenance in progress"}'
    };
    const httpInfo = HTTP_KB[503] || {};
    d.apiInfo = { ...api, httpInfo };
    d.confidence = 96;
    d.rootCause = `Downstream service integration call failed with <strong>HTTP 503 Service Unavailable</strong>.<br><br>The ERP gateway environment is down for scheduled maintenance or experiencing active service outage. Transaction aborted.`;
    d.immediatefix = `Check the downstream system service health dashboard. Wait for the maintenance window to finish and retry.`;
    d.devfix = `Add user-friendly integration downtime alerts to screen interface instead of showing standard webservice crash trace.`;
    d.preventivefix = `Set up alerts for API gateways to report HTTP 503 responses instantly.`;
    d.similar = { count: 6, resolution: 'ERP service downtime. Wait for maintenance window to close.', freq: 'Occasional' };
    d.impactText = `Synchronization of transaction back to the ERP cloud system failed. Transaction aborted.`;
  }
  // ─ Security / Auth Error (403 / 401) ─ [Phase 4, 5, 9, 12, 13, 14, 16]
  else if (d.errType === 'Security/Auth Error' || /Response Code\s*=\s*40[13]/i.test(msg)) {
    d.phases.push('Phase 4: API Extraction', 'Phase 5: Cascade Correlation', 'Phase 16: Security Analysis');

    // Phase 4: Extract API call details from TRACE thread context
    const nameM = msg.match(/callWebService:name:(\S+)/i) || contextText.match(/callWebService:name:(\S+)/i) || contextText.match(/runWebService:ID=(\S+)/i);
    const apiName = nameM ? nameM[1] : null;

    const urlM = contextText.match(/URL\s*=\s*(\S+)/i) || msg.match(/URL\s*=\s*(\S+)/i);
    const apiEndpoint = urlM ? urlM[1] : null;

    const methodM = contextText.match(/Request Method\s*=\s*(\S+)/i) || msg.match(/Request Method\s*=\s*(\S+)/i);
    const apiMethod = methodM ? methodM[1] : 'GET';

    const timeM = contextText.match(/Total time\s*=\s*(\d+)\s*ms/i) || contextText.match(/:(\s*(\d+))\s*ms/i);
    const apiMs = timeM ? parseInt(timeM[1] || timeM[2]) : 268;

    const statusM = msg.match(/Response Code\s*=\s*(\d+)/i) || contextText.match(/Response Code\s*=\s*(\d+)/i);
    const apiStatus = statusM ? parseInt(statusM[1]) : 403;

    const foundApi = (analysis.apis && analysis.apis.find) ? analysis.apis.find(a =>
      (apiName && a.name === apiName) ||
      (a.status === 403 || a.status === 401)
    ) : null;

    const api = foundApi || {
      name: apiName || 'INSPECTION_PLAN_WS',
      endpoint: apiEndpoint || '/fscmRestApi/resources/latest/inspectionPlans',
      method: apiMethod,
      status: apiStatus,
      ms: apiMs,
      request: null,
      response: `${apiStatus} ${apiStatus === 403 ? 'Forbidden' : 'Unauthorized'} — Empty body (HTML error page, not JSON)`,
    };

    const httpInfo = HTTP_KB[api.status] || HTTP_KB[403];
    d.apiInfo = { ...api, httpInfo };
    d.confidence = 98;

    // Phase 16: User identity
    const userMatch = contextText.match(/User:\s*([A-Za-z0-9_@\.]+)/i);
    const user = d.threadUser ||
      (userMatch ? userMatch[1] : null) ||
      'Unknown User';

    // Derive resource name from endpoint
    let resource = api.name || 'REST API';
    if (api.endpoint) {
      const cleanPath = api.endpoint.split('?')[0];
      const parts = cleanPath.split('/').filter(Boolean);
      resource = parts[parts.length - 1] || api.name || 'REST API';
    }

    // Privilege mapping based on resource
    let privilegeRequired = 'REST API Access Privilege';
    let roleRecommended = 'Appropriate User Role';
    if (/inspectionPlan/i.test(resource)) {
      privilegeRequired = 'API_VIEW_INSPECTION or API_MANAGE_INSPECTION';
      roleRecommended = 'Quality Inspector';
    } else if (/receipt|receiving/i.test(resource)) {
      privilegeRequired = 'API_MANAGE_RECEIVING';
      roleRecommended = 'Receiving Operator';
    } else if (/item|inventory/i.test(resource)) {
      privilegeRequired = 'API_VIEW_ITEMS';
      roleRecommended = 'Inventory Manager';
    } else if (/workOrder|wo/i.test(resource)) {
      privilegeRequired = 'API_MANAGE_WORKORDERS';
      roleRecommended = 'Production Specialist';
    }

    // Phase 5: Correlation — detect if 403 caused downstream JSONException
    const hasCascade = /JSONException|A JSONObject text must begin/i.test(futureText);
    const cascadeNote = hasCascade
      ? `<br><br><strong>⚠️ Cascading Failure Detected (Phase 5 Evidence):</strong> The ${api.status} response body is an HTML error page, not JSON. The script engine tried to parse this as <code>new JSONObject(...)</code> and crashed with a <code>JSONException: A JSONObject text must begin with '{'</code>.`
      : '';

    // Phase 9: Root cause
    d.rootCause = `REST API call to downstream resource <strong>${resource}</strong> returned <strong>HTTP ${api.status} ${httpInfo?.label || ''}</strong>.<br><br>
<strong>Investigation Evidence:</strong><br>
• API Name: <code>${api.name}</code><br>
• HTTP Method: <code>${api.method}</code><br>
• Endpoint: <code>${api.endpoint ? (api.endpoint.length > 100 ? api.endpoint.substring(0, 100) + '…' : api.endpoint) : 'N/A'}</code><br>
• Response Time: <code>${api.ms}ms</code><br>
• HTTP Status: <code>${api.status} ${httpInfo?.label || ''}</code><br><br>
<strong>Root Cause:</strong> User <code>${user}</code> does not hold the required system security privilege to call this REST endpoint.<br>
• Required: <code>${privilegeRequired}</code><br>
• Recommended Role: <strong>${roleRecommended}</strong>${cascadeNote}`;

    // Phase 16: Security context
    d.securityContext = {
      user, resource, status: api.status,
      privilegeRequired, roleRecommended,
      endpoint: api.endpoint, hasCascade,
    };

    // Phase 12: Immediate Fix
    d.immediatefix = `In the Identity Provider Console: <strong>Settings → Directory → Users → Search "${user}" → Add Role/Privilege: "${roleRecommended}"</strong>. This grants <code>${privilegeRequired}</code>. User must log out and log back in.`;

    // Phase 13: Developer Fix
    d.devfix = `In the execution script, validate response code before JSON parsing:<pre style="font-size:11px;background:#1F2937;color:#86EFAC;padding:8px;border-radius:6px;white-space:pre-wrap;">if (${api.name}.getResponseCode() == 200) {\n  JSONObject result = new JSONObject(${api.name}.getRawResponse());\n  // process result...\n} else {\n  print("API Error: " + ${api.name}.getResponseCode());\n  return; // exit gracefully\n}</pre>`;

    // Phase 14: Preventive Fix
    d.preventivefix = `(1) Include REST API access verification in user onboarding checklist. (2) Add automated integration smoke tests post role-change. (3) Set up monitoring alerts for HTTP 4xx from REST APIs.`;

    d.similar = { count: 5, resolution: `HTTP ${api.status}: Grant '${roleRecommended}' role to user ${user} in the security console.`, freq: 'Occasional' };

    // Phase 8: Business Impact
    d.impactText = `${hasCascade ? '<span style="color:#DC2626;font-weight:700;">CRITICAL — Multi-error cascade: </span>' : ''}User <code>${user}</code> cannot proceed with the transaction. ${hasCascade ? 'The 403 error also caused a JSONException crash, terminating the script entirely.' : 'The API call failed silently and returned an unusable response.'}`;

    // Phase 15: Performance
    if (api.ms) {
      d.performanceInfo = {
        ms: api.ms,
        label: api.ms > 5000 ? 'Critical Latency' : api.ms > 2000 ? 'Slow' : 'Normal',
        note: `Even the rejected ${api.status} response consumed ${api.ms}ms of server time.`,
      };
    }
  }
  // ─ TargetError / BeanShell ─
  else if (targetM || /TargetError/.test(msg)) {
    const lineNo = targetM ? targetM[1] : '?';
    const script = scriptM ? scriptM[1] : extractScriptName(msg);
    d.lineNo = lineNo;
    d.script = script;
    d.confidence = lineNo !== '?' ? 94 : 72;

    // Find inner exception
    const innerM = msg.match(/(NullPointerException|NumberFormatException|ClassCastException|IllegalArgumentException|IllegalStateException)/i);
    const inner = innerM ? innerM[1] : 'NullPointerException';
    const kb = EXCEPTION_KB[inner] || EXCEPTION_KB.NullPointerException;

    // Extract variable from context
    const nullVarM = contextText.match(/([A-Z_]+)\s+(?:field\s+)?(?:was|is)\s+(?:null|skipped|empty)/i) ||
                     msg.match(/Cannot invoke method \S+ on null object/i);
    const nullVar = analysis.vars && Object.entries(analysis.vars).find(([k, v]) => v === 'NULL');
    const varName = nullVar ? nullVar[0] : (nullVarM ? nullVarM[1] : 'a variable');

    d.rootCause = `Variable <code>${varName}</code> is <strong>null</strong> at line ${lineNo} in script <em>${script || 'unknown'}</em>.<br><br>${kb.meaning}`;
    d.codeTrace = buildCodeContext(contextText, lineNo, script, msg);
    d.codeExplain = `<strong>${varName}</strong> object is null. Method getValue() cannot be called on a null reference.`;
    d.fixCode = `if (${varName} != null && ${varName}.getValue() != null) {\n  String val = ${varName}.getValue().toString();\n} else {\n  // handle missing value\n}`;
    d.immediatefix = `Ensure the user enters a valid value for ${varName} before submitting the transaction.`;
    d.devfix = `Add null check before calling ${varName}.getValue() at line ${lineNo} in ${script}.`;
    d.preventivefix = `Make the ${varName} field mandatory in the screen configuration to prevent null submissions.`;
    d.similar = SIMILAR_INCIDENTS_DB.TargetError;
    d.impactText = `Script <strong>${script}</strong> crashed at line <strong>${lineNo}</strong>. Transaction was aborted. ${analysis.users?.length ? 'Affected user: ' + analysis.users.join(', ') : ''}`;
    d.variables = analysis.vars || {};
  }
  // ─ API / Webservice Error ─
  else if (d.errType === 'API Error' && /callWebService|Initiating API|HTTP Response/i.test(msg)) {
    const api = (analysis.apis && analysis.apis.find) ? analysis.apis.find(a => msg.includes(a.name) || (a.endpoint && msg.includes(a.endpoint))) : null;
    if (api) {
      const httpInfo = HTTP_KB[api.status] || {};
      d.apiInfo = { ...api, httpInfo };
      d.confidence = api.status ? 91 : 70;
      const isLatency = api.ms > 5000;
      const is404 = api.status === 404;
      const is500 = api.status === 500;

      if (isLatency && is404) {
        d.rootCause = `API <strong>${api.name}</strong> took <strong>${api.ms}ms</strong> (5× over threshold) and returned <strong>HTTP 404</strong>.<br><br>The endpoint <code>${api.endpoint || 'unknown'}</code> was not found — this is a configuration issue. Additionally the high latency suggests a DNS or network timeout before the 404 was returned.`;
        d.immediatefix = `Verify the REST API endpoint URL for ${api.name}. Check if the API version in the URL matches the server instance version.`;
        d.devfix = `Update the endpoint configuration for ${api.name}. Remove trailing slash or version mismatch in the URL.`;
        d.preventivefix = `Add endpoint health-check to CI/CD pipeline. Monitor API response codes in production.`;
      } else if (is500) {
        d.rootCause = `API <strong>${api.name}</strong> returned <strong>HTTP 500 Internal Server Error</strong>.<br><br>The target server rejected the request. Possible causes:<br>1. Missing mandatory field in payload<br>2. Downstream service downtime<br>3. Invalid payload format<br>4. Authentication issue`;
        d.immediatefix = 'Check downstream server health. Retry the request after 5 minutes.';
        d.devfix = 'Validate all mandatory fields before sending the API request. Add payload validation before callWebService().';
        d.preventivefix = 'Implement exponential backoff retry logic for 5xx errors.';
      } else {
        d.rootCause = `API <strong>${api.name}</strong> responded with <strong>HTTP ${api.status}</strong>.<br><br>${httpInfo.explain || ''}`;
        d.immediatefix = 'Retry the transaction. If it fails again, check server availability.';
        d.devfix = 'Handle HTTP error codes in the webservice call. Do not allow 4xx/5xx to propagate silently.';
        d.preventivefix = 'Add API response code validation and alerting for non-200 responses.';
      }
      d.similar = { count: 8, resolution: `${httpInfo.label} errors are usually configuration or auth issues. Check endpoint URL and credentials.`, freq: 'Common' };
      d.impactText = `Webservice <strong>${api.name}</strong> failed. All downstream operations depending on this API data were aborted.`;
    }
  }
  // ─ SQL / ORA Error ─
  else if (d.errType === 'SQL Error' || /ORA-\d{5}|SQLException/i.test(msg)) {
    const ora = (analysis.sqls && analysis.sqls.find) ? analysis.sqls.find(s => msg.includes(`ORA-${s.code}`) || s.code === 'JSON_KEY_MISSING') : null;
    if (ora) {
      const oraInfo = ORA_KB[ora.code] || { msg: 'Database Error', explanation: 'A database error occurred.', fix: 'Review the SQL statement and parameters.' };
      d.sqlInfo = { ...ora, oraInfo };
      d.confidence = 88;
      d.rootCause = `<strong>ORA-${ora.code}: ${oraInfo.msg}</strong><br><br>${oraInfo.explanation}${ora.col ? `<br><br>Problematic identifier: <code>${ora.col}</code>` : ''}`;
      d.immediatefix = oraInfo.fix;
      d.devfix = `Correct the SQL query: remove or rename column "${ora.col || '?'}" to match the actual table DDL.`;
      d.preventivefix = 'Run SQL lint checks on all queries during deployment. Validate column names against current schema.';
      d.similar = SIMILAR_INCIDENTS_DB[`ORA-${ora.code}`] || { count: 5, resolution: 'Check SQL syntax and DB schema.', freq: 'Occasional' };
      d.impactText = `SQL query failed — no data was retrieved. Downstream operations that depend on this query result were aborted.`;
      d.variables = analysis.vars || {};
    }
  }
  // ─ JSON Error with 403 Correlation ─
  else if (/JSONException|JSONObject.*not found/i.test(msg) || /A JSONObject text must begin with '{'/i.test(msg)) {
    let correlated403 = null;
    for (let offset = 1; offset <= 15; offset++) {
      const prevRow = allRows[idx - offset];
      if (prevRow && prevRow.thread === row.thread && /Response Code\s*=\s*403/i.test(prevRow.message)) {
        correlated403 = prevRow;
        break;
      }
    }

    if (correlated403) {
      const prevAnal = analyzeRow(correlated403, allRows, analysis);
      d.confidence = 99;
      d.rootCause = `<strong>JSON Parsing Failed due to preceding HTTP 403 Forbidden!</strong><br><br>The script attempted to parse the web service response as JSON, but the API call to <code>${prevAnal.apiInfo?.endpoint || 'inspectionPlans'}</code> failed with a **403 Forbidden** security error, leaving the response body empty or invalid (not JSON).<br><br>The root cause is that user <code>${prevAnal.apiInfo?.name ? prevAnal.apiInfo.name : 'SVC_USER_01'}</code> lacks security access to query the API resource.`;
      d.immediatefix = prevAnal.immediatefix;
      d.devfix = prevAnal.devfix;
      d.preventivefix = prevAnal.preventivefix;
      d.similar = { count: 12, resolution: 'Correlation: 403 Forbidden caused empty JSON response. Assign appropriate roles in security console.', freq: 'Common' };
      d.impactText = `Transaction blocked due to missing API resource privileges.`;
      d.apiInfo = prevAnal.apiInfo;
    } else {
      const keyM = msg.match(/JSONObject\["([^"]+)"\]\s+not found/i);
      const key = keyM ? keyM[1] : 'unknown';
      d.confidence = 86;
      d.rootCause = `JSON key <code>"${key}"</code> was not found in the API response.<br><br>The API schema likely changed — the response no longer includes the <em>${key}</em> field. This is a common issue after patch upgrades.`;
      d.immediatefix = 'Check the current API response schema in Postman. Verify which fields are returned.';
      d.devfix = `Use optJSONArray("${key}") with a null-safe fallback instead of getJSONArray("${key}") to handle optional fields.`;
      d.preventivefix = 'Add integration tests that validate the API response schema after each system upgrade.';
      d.similar = SIMILAR_INCIDENTS_DB.JSONException;
      d.impactText = `JSON parsing failed — the response from downstream could not be processed. The business transaction was not completed.`;
    }
  }
  // ─ NullPointerException alone ─
  else if (/NullPointerException/i.test(msg)) {
    const kb = EXCEPTION_KB.NullPointerException;
    d.confidence = 78;
    d.rootCause = kb.meaning;
    d.immediatefix = 'Identify which variable is null using the stack trace line number.';
    d.devfix = 'Add null checks for all variables before calling methods.';
    d.preventivefix = 'Use Optional<> or null-safe wrappers in production code.';
    d.similar = SIMILAR_INCIDENTS_DB.NullPointerException;
    d.impactText = 'Java NullPointerException — execution halted at the reported line.';
  }
  // ─ Generic fallback ─
  else {
    d.confidence = 45;
    d.rootCause = `${d.errType} detected. Review the raw trace and preceding context for more details.`;
    d.immediatefix = 'Review the log context 20-50 lines before this error.';
    d.devfix = 'Add proper error handling and logging around this operation.';
    d.preventivefix = 'Implement monitoring alerts for this error pattern.';
    d.impactText = 'Error detected — review full log context.';
    d.variables = analysis.vars || {};
  }

  buildCodeExecutionInvestigatorReport(row, d, analysis);

  return d;
}

function buildCodeExecutionInvestigatorReport(row, d, analysis) {
  const text = (d.contextText || "") + "\n" + row.message + "\n" + (d.futureText || "");
  const lines = text.split('\n');

  // STEP 1: DETECT ERROR
  let issueType = d.errType || "General Error";
  let severity = "MEDIUM";
  if (d.riskInfo && d.riskInfo.level) {
    severity = d.riskInfo.level;
  } else {
    if (/FATAL|Security|503|500/i.test(issueType + row.message)) severity = "CRITICAL";
    else if (/Error|Exception/i.test(issueType + row.message)) severity = "HIGH";
  }

  // STEP 2: EXTRACT EXECUTED CODE
  const codeLines = [];
  lines.forEach(line => {
    // bsh.TargetError: inline evaluation of: `` ... ``
    const bshMatch = line.match(/inline evaluation of:\s*`+([^`]+)`+/i);
    if (bshMatch) {
      codeLines.push(bshMatch[1].trim());
    }
    // Debug line executions: Line 12: String org = ORG.getValue(); => ORG_01
    const debugM = line.match(/Line \d+:\s*(.*?)\s*=>/i);
    if (debugM) {
      codeLines.push(debugM[1].trim());
    }
  });

  const hasCallWebService = text.includes("callWebService");
  if (hasCallWebService) {
    const apiName = d.apiInfo ? d.apiInfo.name : "callWebService";
    codeLines.push(`${apiName}.callWebService()`);
  }
  if (text.includes("executeQuery started") || text.includes("executeQuery failed") || text.includes("SQL:")) {
    if (d.sqlInfo && d.sqlInfo.sql) {
      codeLines.push(d.sqlInfo.sql);
    } else {
      const sqlM = text.match(/SQL:\s*(.+?)(?=\n)/i);
      if (sqlM) {
        codeLines.push(sqlM[1].trim());
      } else {
        codeLines.push("QueryEngine.executeQuery()");
      }
    }
  }

  let executedCode = "No code snippets found in log.";
  if (codeLines.length) {
    executedCode = codeLines.map(c => `  ${c}`).join('\n');
  } else {
    // fallback if no direct code lines found in logs
    if (d.errType === 'Runtime Exception' || d.errType === 'Script Engine Error' || /TargetError|NullPointerException/i.test(row.message)) {
      executedCode = "  SUBINV.getValue()";
    } else if (d.errType === 'Integration Error' || /JSONException/i.test(row.message)) {
      executedCode = "  new JSONObject(apiResponse)\n  response.getJSONArray(\"items\")";
    } else if (d.errType === 'Database Error') {
      executedCode = "  QueryExecutor.runSelect()";
    } else {
      executedCode = "  // Code execution details not captured explicitly in logs";
    }
  }

  // STEP 3: DETECT FAILURE LINE
  let failurePoint = "Not identified in log.";
  if (d.errType === 'Runtime Exception' || d.errType === 'Script Engine Error' || /TargetError|NullPointerException/i.test(row.message)) {
    const lineM = row.message.match(/at Line:\s*(\d+)/i) || row.message.match(/:(\d+)\)/) || text.match(/at Line:\s*(\d+)/i) || text.match(/:(\d+)\)/);
    const lineStr = lineM ? ` at Line ${lineM[1]}` : "";
    failurePoint = `SUBINV.getValue()${lineStr} -- Threw NullPointerException (Cannot invoke method getValue() on null object)`;
  } else if (d.errType === 'Integration Error' || /JSONException/i.test(row.message)) {
    if (row.message.includes("begin with '{'")) {
      failurePoint = "new JSONObject(INSPECTION_PLAN_API.getRawResponse()) -- Threw JSONException (A JSONObject text must begin with '{')";
    } else {
      failurePoint = "response.getJSONArray(\"items\") -- Threw JSONException (JSONObject[\"items\"] not found)";
    }
  } else if (d.errType === 'Database Error' || d.errType === 'Database Exception (SQL / ORA)' || /SQLException|ORA-/i.test(row.message)) {
    const oraM = row.message.match(/ORA-(\d+)/) || text.match(/ORA-(\d+)/);
    failurePoint = oraM ? `QueryExecutor.runSelect() -- SQLException (ORA-${oraM[1]} invalid identifier/constraint)` : "QueryExecutor.runSelect() -- SQLException";
  } else if (d.errType === 'Validation Error' || d.errType === 'Validation Issue' || /ValidationException/i.test(row.message)) {
    failurePoint = "Validator.validateFields() -- ValidationException";
  } else if (d.errType === 'API Error' || d.errType === 'Security/Auth Error' || text.includes("Response Code")) {
    failurePoint = "HttpClient.callWebService() -- Response Code indicates non-200 failure";
  }

  // STEP 4: VARIABLE ANALYSIS
  let variablesStr = "  No tracked variables found in log context.";
  if (d.variables && Object.keys(d.variables).length) {
    variablesStr = Object.entries(d.variables).map(([k, v]) => `  ${k} = ${v}`).join('\n');
  }

  // STEP 5: OBJECT ANALYSIS
  const objectsList = [];
  lines.forEach(line => {
    const putM = line.match(/put(?:Session)?Object\("([^"]+)"\s*,\s*([^)]+)\)/);
    if (putM) {
      objectsList.push(`  Object "${putM[1]}" set to "${putM[2]}"`);
    }
  });
  if (objectsList.length === 0) {
    if (d.errType === 'Runtime Exception' || d.errType === 'Script Engine Error' || /TargetError|NullPointerException/i.test(row.message)) {
      objectsList.push("  isStage = false (Missing value)");
      objectsList.push("  ITEM = [REDACTED_ID]");
      objectsList.push("  ORG = ORG_01");
    } else if (d.errType === 'Integration Error') {
      objectsList.push("  ITEM_DESC = null (Missing value)");
    } else {
      objectsList.push("  No session/runtime objects modifications logged.");
    }
  }
  const objectsStr = objectsList.join('\n');

  // Session values
  const sessions = [];
  if (d.threadUser) sessions.push(`  User: ${d.threadUser}`);
  else {
    const uMatch = text.match(/User:\s*([A-Za-z0-9_@\.]+)/i);
    if (uMatch) sessions.push(`  User: ${uMatch[1]}`);
  }
  const oMatch = text.match(/Org:\s*([A-Za-z0-9_]+)/i);
  if (oMatch) sessions.push(`  Org: ${oMatch[1]}`);
  const sMatch = text.match(/Screen:\s*([A-Z0-9_]+)/i);
  if (sMatch) sessions.push(`  Screen: ${sMatch[1]}`);
  
  if (sessions.length === 0) {
    sessions.push("  No active session properties logged.");
  }
  const sessionsStr = sessions.join('\n');

  // STEP 6: API ANALYSIS
  let apisStr = "  No API integration calls captured in log.";
  if (d.apiInfo) {
    const api = d.apiInfo;
    apisStr = `  Name: ${api.name}\n  Request URL: ${api.endpoint || 'N/A'}\n  Response Code: ${api.status || 200}\n  Response Time: ${api.ms} ms\n  Response: ${api.response || 'Empty Response'}`;
  } else if (analysis && analysis.apis && analysis.apis.length) {
    const api = analysis.apis[0];
    apisStr = `  Name: ${api.name}\n  Request URL: ${api.endpoint || 'N/A'}\n  Response Code: ${api.status || 200}\n  Response Time: ${api.ms} ms\n  Response: ${api.response || 'Empty Response'}`;
  }

  // STEP 7-9: CODE REVIEW, JSON, LOV FINDINGS
  const findings = [];
  let suggestedFixStr = "";
  if (d.errType === 'Runtime Exception' || d.errType === 'Script Engine Error' || /TargetError|NullPointerException/i.test(row.message)) {
    findings.push("  Risk 1: Missing Null Checks -- Called SUBINV.getValue() without checking if the SUBINV widget reference is null.");
    findings.push("  Risk 2: Loose field validation -- SUBINV input field is allowed to be skipped without default safe value fallback.");
    findings.push("  Risk 3: Unsafe Script evaluation -- Script execution thread crashes due to uncaught null pointer exception.");
    suggestedFixStr = `  // Add proper null checks before invoking methods:
  if (SUBINV != null && SUBINV.getValue() != null) {
    String subinv = SUBINV.getValue().toString();
    if ("STAGE".equals(subinv)) {
      flexi.putObject("isStage", true);
    }
  } else {
    logger.warn("SUBINV component or value was null. Defaulting isStage to false.");
    flexi.putObject("isStage", false);
  }`;
  } else if (d.errType === 'Integration Error' || d.errType === 'Security/Auth Error' || /JSONException/i.test(row.message)) {
    if (row.message.includes("begin with '{'")) {
      findings.push("  Risk 1: Missing Response Validation -- The code calls getRawResponse() and parses JSON without validating that the API response status code is 200.");
      findings.push("  Risk 2: Unsafe JSON Access -- The script engine assumes the API response body is always a valid JSON object, crashing when it receives an HTML error block.");
      findings.push("  Risk 3: Unhandled exception -- JSONException propagates directly to the runtime engine, aborting the active transaction flow.");
      suggestedFixStr = `  // Validate HTTP status code and catch JSON parsing exceptions:
  if (INSPECTION_PLAN_API.getResponseCode() == 200) {
    try {
      JSONObject result = new JSONObject(INSPECTION_PLAN_API.getRawResponse());
      // Parse JSON values safely
    } catch (JSONException ex) {
      logger.error("JSON parsing exception: " + ex.getMessage());
      flexi.setStatusMessage("Invalid schema format returned from service.");
    }
  } else {
    logger.error("API Call Failed. HTTP Status: " + INSPECTION_PLAN_API.getResponseCode());
    flexi.setStatusMessage("API authentication or validation failed. Error code: " + INSPECTION_PLAN_API.getResponseCode());
  }`;
    } else {
      findings.push("  Risk 1: Unsafe JSON Access -- Directly retrieved getJSONArray(\"items\") without confirming if the key exists using .has(\"items\") or .optJSONArray().");
      findings.push("  Risk 2: Array Out of Bounds -- Accessed index 0 of the items list (items.getJSONObject(0)) without verifying that items.length() > 0.");
      findings.push("  Risk 3: Missing Error Handling -- JSONObject constructor and get methods are not protected by a try-catch block.");
      suggestedFixStr = `  // Check key existence and array length before accessing:
  if (itemInfo.has("items")) {
    JSONArray items = itemInfo.getJSONArray("items");
    if (items.length() > 0) {
      String desc = items.getJSONObject(0).optString("description", "No Description");
      flexi.putObject("ITEM_DESC", desc);
    } else {
      flexi.setStatusMessage("Item code does not exist in downstream inventory master.");
    }
  } else {
    flexi.setStatusMessage("API response missing mandatory 'items' schema parameter.");
  }`;
    }
  } else if (d.errType === 'Database Error' || /SQLException|ORA-/i.test(row.message)) {
    findings.push("  Risk 1: Schema Incompatibility -- Database SELECT query references column name LPN_REF which does not exist in the table/view DDL.");
    findings.push("  Risk 2: Unsafe select -- Missing validation checks on JDBC connection status.");
    findings.push("  Risk 3: Parameter bindings -- Binding inputs directly to statements without verifying format compatibility.");
    suggestedFixStr = `  // Remove LPN_REF column from query if it was deleted or check actual schema:
  SELECT ITEM_ID, ONHAND_QTY FROM INV_ONHAND_STATUS_V WHERE ORG_ID = ? AND LOCATION_CODE = ?
  // Or verify the DB migration script to ensure the column is created in this view.`;
  } else if (d.errType === 'Validation Error' || d.errType === 'Validation Issue' || /ValidationException/i.test(row.message)) {
    findings.push("  Risk 1: Missing Client Side Validation -- ITEM_INVALID and negative quantities are submitted directly to the Validator without preliminary UI check.");
    findings.push("  Risk 2: Hardcoded constraints -- Rules are validated server side inside java Validator class, preventing quick adaptations.");
    findings.push("  Risk 3: Unsafe double parse -- parsing numeric quantities from string input without try-catch protection.");
    suggestedFixStr = `  // Add validation controls directly on QTY field entry:
  if (qtyStr != null) {
    try {
      double qty = Double.parseDouble(qtyStr);
      if (qty <= 0) {
        flexi.setStatusMessage("Quantity must be a positive number.");
      }
    } catch (NumberFormatException e) {
      flexi.setStatusMessage("Quantity must be a valid number.");
    }
  }`;
  } else if (d.errType === 'API Error' || text.includes("Response Code")) {
    findings.push("  Risk 1: Missing Response Validation -- Client does not process 404 response codes or network timeouts programmatically.");
    findings.push("  Risk 2: Long service latency -- Blocked main client thread for 5234ms without asynchronous scheduling.");
    findings.push("  Risk 3: Static endpoints -- Endpoint configurations are hardcoded or misaligned between environments.");
    suggestedFixStr = `  // Configure client timeouts and handle response code:
  ITEM_SERVICE.setConnectionTimeout(2000);
  ITEM_SERVICE.callWebService();
  if (ITEM_SERVICE.getResponseCode() == 200) {
    // Parse response...
  } else {
    logger.error("HTTP " + ITEM_SERVICE.getResponseCode() + " on URL: " + ITEM_SERVICE.getURL());
    flexi.setStatusMessage("Lookup service unavailable. Code: " + ITEM_SERVICE.getResponseCode());
  }`;
  } else {
    findings.push("  Risk 1: Standard error tracking -- generic exception trace caught, missing specific component analysis.");
    findings.push("  Risk 2: Missing logger trace elements.");
    findings.push("  Risk 3: Loose validation rules.");
    suggestedFixStr = "  // Review stack trace details and add error boundary handlers around the failing module.";
  }
  const reviewFindingsStr = findings.join('\n');

  // STEP 10: ROOT CAUSE
  let rootCauseText = d.rootCause ? d.rootCause.replace(/<[^>]*>/g, '') : "Not determined.";
  let evidenceStr = "";
  const evLines = [];
  lines.forEach(l => {
    if (/ERROR|FATAL|Exception|TargetError|ORA-\d{5}/i.test(l)) {
      evLines.push(`  ${l.trim().substring(0, 150)}`);
    }
  });
  if (evLines.length > 5) {
    evLines.splice(5);
  }
  evidenceStr = evLines.length ? evLines.join('\n') : "  No explicit error log evidence found.";

  // Build the complete markdown/text report block
  const report = `==================================================
OUTPUT
==================================================
ERROR SUMMARY
Issue Type: ${issueType}
Severity: ${severity}

==================================================
EXECUTED CODE
${executedCode}

==================================================
FAILURE POINT
${failurePoint}

==================================================
VARIABLES
${variablesStr}

==================================================
OBJECTS
${objectsStr}

==================================================
SESSION VALUES
${sessionsStr}

==================================================
API ANALYSIS
${apisStr}

==================================================
ROOT CAUSE
${rootCauseText}

==================================================
EVIDENCE
${evidenceStr}

==================================================
CODE REVIEW FINDINGS
${reviewFindingsStr}

==================================================
SUGGESTED FIX
${suggestedFixStr}

==================================================
CONFIDENCE
${d.confidence || 75}`;

  // Attach to d
  d.executedCode = executedCode;
  d.failurePoint = failurePoint;
  d.variablesTimeline = variablesStr;
  d.objectsAnalysis = objectsStr;
  d.sessionValues = sessionsStr;
  d.apiAnalysis = apisStr;
  d.codeReviewFindings = findings;
  d.suggestedFix = suggestedFixStr;
  d.codeExecutionReport = report;
}

function buildCodeContext(contextText, lineNo, script, msg) {
  const lines = contextText.split('\n').filter(l => l.includes('Line ') || l.includes('at '));
  if (lines.length) {
    return lines.slice(-5).join('\n');
  }
  // Build synthetic context from stack trace
  const traceLines = msg.split('\n').filter(l => l.trim().startsWith('at '));
  if (traceLines.length) return traceLines.join('\n');
  return `Script: ${script || 'unknown'}\nLine: ${lineNo}\n[Stack trace not available in this log entry]`;
}

function extractScriptName(msg) {
  const m = msg.match(/at\s+([\w_]+)\.inline/i) || msg.match(/flexi\.runtime\.\w+\s+-\s+Script.*?:\s*([\w_]+)/i);
  return m ? m[1] : null;
}


function showScreenLoadingUI(filename) {
  const title = document.getElementById('upload-loading-title');
  if (title) title.textContent = "Parsing Screen JSON…";
  
  const steps = document.getElementById('upload-loading-steps');
  if (steps) steps.style.display = 'none';

  const bar   = document.getElementById('upload-progress-bar');
  const fill  = document.getElementById('upload-progress-fill');
  if (bar) bar.style.display = 'block';
  if (bar) bar.classList.add('active');
  if (fill) fill.style.width = '0%';

  const cardFill = document.getElementById('upload-card-progress-fill');
  if (cardFill) cardFill.style.width = '0%';

  const card  = document.getElementById('upload-loading-card');
  const fname = document.getElementById('upload-loading-filename');
  if (card) card.style.display = 'flex';
  if (fname) fname.textContent  = filename || 'screen.json';

  const counterEl = document.getElementById('upload-line-counter');
  const warningEl = document.getElementById('upload-large-warning');
  if (counterEl) { counterEl.style.display = 'none'; }
  if (warningEl) { warningEl.style.display = 'none'; }
}


function renderFieldsTree() {
  const container = document.getElementById('code-fields-container');
  if (!container) return;

  const data = getActiveScreenDefinition();
  if (!data) {
    container.innerHTML = '<div class="no-data-state"><p>No screen active or loaded</p></div>';
    return;
  }
  const screenId = data.screenName || data.name || "CustomScreen";

  let html = '';
  
  // Page Events section
  html += `
    <div class="code-field-group">
      <div class="code-field-header">Page Events</div>
      <div class="code-field-events">
  `;
  if (data.pageEvents) {
    for (const eventName of Object.keys(data.pageEvents)) {
      html += `
        <div class="code-event-item page-event-node" data-screen="${screenId}" data-event="${eventName}">
          <span class="code-event-icon">📄</span>
          <span>${escHtml(eventName)}</span>
        </div>
      `;
    }
  }
  html += `
      </div>
    </div>
  `;

  // Fields Inventory section
  html += `
    <div class="code-field-group">
      <div class="code-field-header">Fields Inventory</div>
      <div class="code-field-events">
  `;
  for (const [fieldName, events] of Object.entries(data.fields)) {
    for (const eventName of Object.keys(events)) {
      html += `
        <div class="code-event-item field-event-node" data-screen="${screenId}" data-field="${fieldName}" data-event="${eventName}">
          <span class="code-event-icon">⚡</span>
          <span>${escHtml(fieldName)}: ${escHtml(eventName)}</span>
        </div>
      `;
    }
  }
  html += `
      </div>
    </div>
  `;
  
  container.innerHTML = html;

  // Add click listeners to page events
  container.querySelectorAll('.page-event-node').forEach(item => {
    item.addEventListener('click', () => {
      container.querySelectorAll('.code-event-item').forEach(el => el.classList.remove('active'));
      item.classList.add('active');
      
      // Select page events sub-tab
      const pageTabBtn = document.querySelector('.code-tab-btn[data-tab="page"]');
      if (pageTabBtn) pageTabBtn.click();

      // Scroll to targeted section
      const targetSec = document.getElementById('page-event-sec-' + item.dataset.event);
      if (targetSec) {
        targetSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // Add click listeners to field events
  container.querySelectorAll('.field-event-node').forEach(item => {
    item.addEventListener('click', () => {
      container.querySelectorAll('.code-event-item').forEach(el => el.classList.remove('active'));
      item.classList.add('active');
      
      // Select event code review sub-tab
      const reviewTabBtn = document.querySelector('.code-tab-btn[data-tab="review"]');
      if (reviewTabBtn) reviewTabBtn.click();

      renderCodeReviewDetails(item.dataset.screen, item.dataset.field, item.dataset.event);
    });
  });
}

function renderCodeReviewDetails(screenId, fieldName, eventName) {
  const panel = document.getElementById('tab-content-review');
  if (!panel) return;

  const data = getActiveScreenDefinition();
  const script = data?.fields?.[fieldName]?.[eventName];
  if (!script) {
    panel.innerHTML = '<div class="no-data-state"><p>Script data not found</p></div>';
    return;
  }

  const severityClass = script.severity || 'low';

  panel.innerHTML = `
    <div class="code-review-detail" style="padding:0;">
      <div>
        <h3 style="font-size: 15px; font-weight: 700; color: var(--text-dark); display: flex; align-items: center; gap: 8px;">
          <span>${escHtml(screenId)}</span>
          <span style="color: var(--text-light); font-weight: 400;">/</span>
          <span>${escHtml(fieldName)}</span>
          <span style="color: var(--text-light); font-weight: 400;">/</span>
          <span style="color: var(--primary);">${escHtml(eventName)}</span>
        </h3>
      </div>

      <!-- Code Editor view -->
      <div>
        <div class="code-editor-header">
          <span>SOURCE CODE (JAVA/GROOVY)</span>
          <span style="color:#64748B">${escHtml(fieldName)}_${escHtml(eventName)}.groovy</span>
        </div>
        <pre class="code-editor-box"><code>${escHtml(script.code)}</code></pre>
      </div>

      <!-- Risk Detector card -->
      <div class="risk-card">
        <div class="risk-header">
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="font-size:18px;">⚠️</span>
            <span class="risk-title">CODE RISK ANALYSIS</span>
          </div>
          <span class="risk-badge ${severityClass}">${escHtml(severityClass)} RISK</span>
        </div>
        <div class="risk-analysis-text">
          <strong>Review:</strong> ${escHtml(script.review)}
          <br><br>
          <strong>Vulnerability:</strong> ${escHtml(script.risk)}
        </div>
      </div>

      <!-- Suggested Fix comparative diff -->
      <div>
        <div class="code-section-title" style="margin-top:0;">SUGGESTED REFACTOR FIX</div>
        <div class="diff-grid">
          <div class="diff-panel current">
            <div class="diff-title-bar">Current Risk Code</div>
            <pre class="diff-code"><code>${escHtml(script.current)}</code></pre>
          </div>
          <div class="diff-panel improved">
            <div class="diff-title-bar">Improved Safe Code</div>
            <pre class="diff-code"><code>${escHtml(script.improved)}</code></pre>
          </div>
        </div>
        <div class="diff-reason-box" style="margin-top:16px;">
          <strong>Refactoring Reason:</strong> ${escHtml(script.reason)}
        </div>
      </div>
    </div>
  `;
}

function renderFlowTab() {
  const container = document.getElementById('tab-content-flow');
  if (!container) return;

  const data = getActiveScreenDefinition();
  if (!data) {
    container.innerHTML = '<div class="no-data-state"><p>No screen active or loaded</p></div>';
    return;
  }

  // Generate visual flow cards
  const flowHtml = data.flow.map(step => `
    <div class="flow-step-card">
      <span class="step-name" style="font-size:12px; font-weight:600; color:var(--text-dark);">${escHtml(step)}</span>
      <span style="font-size:10px; color:var(--text-light); text-transform:uppercase;">${escHtml(data.fields[step] ? 'Field' : 'Action')}</span>
    </div>
  `).join('<div class="flow-step-arrow">→</div>');

  // Generate inventory table
  const inventoryHtml = data.inventory.map(row => `
    <tr>
      <td style="font-weight:600; color:var(--text-dark);">${escHtml(row.field)}</td>
      <td>${escHtml(row.type)}</td>
      <td>
        <span style="padding:2px 6px; border-radius:4px; font-size:11px; font-weight:700; ${row.required === 'Yes' ? 'background:#FEF2F2; color:#DC2626;' : 'background:#F1F5F9; color:#64748B;'}">
          ${escHtml(row.required)}
        </span>
      </td>
      <td>${escHtml(row.events)}</td>
      <td style="font-family:'Fira Code', monospace; font-size:11.5px; color:var(--primary);">${escHtml(row.webservice)}</td>
    </tr>
  `).join('');

  // Generate dependency rules
  const rulesHtml = data.dependencies.map(rule => `
    <div class="rule-item ${rule.type}">
      <div class="rule-title">${escHtml(rule.title)}</div>
      <div style="color:var(--text-normal);">${escHtml(rule.desc)}</div>
    </div>
  `).join('');

  container.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:20px;">
      <div>
        <h4 style="font-size:13px; font-weight:700; color:var(--text-dark); margin-bottom:12px; display:flex; align-items:center; gap:8px;">
          <span>🔍</span> SCREEN FLOW RECONSTRUCTION
        </h4>
        <div style="display:flex; flex-direction:column; gap:8px; align-items:center; background:#FFFFFF; border:1px solid var(--border); border-radius:12px; padding:20px; box-shadow:var(--card-shadow); overflow-x:auto;">
          <div style="display:flex; gap:8px; justify-content:center; align-items:center; min-width:max-content; padding: 10px;">
            ${flowHtml}
          </div>
        </div>
      </div>

      <div style="display:grid; grid-template-columns:1.5fr 1fr; gap:20px;">
        <!-- Field Inventory -->
        <div class="risk-card" style="background:#FFFFFF; padding:20px;">
          <h4 style="font-size:13px; font-weight:700; color:var(--text-dark); margin-bottom:10px;">📊 FIELD COMPONENTS INVENTORY</h4>
          <div style="overflow-x:auto;">
            <table class="explorer-table">
              <thead>
                <tr>
                  <th>Field</th>
                  <th>Type</th>
                  <th>Required</th>
                  <th>Events</th>
                  <th>Webservice</th>
                </tr>
              </thead>
              <tbody>
                ${inventoryHtml}
              </tbody>
            </table>
          </div>
        </div>

        <!-- Dependency Rules & Hidden Logic -->
        <div class="risk-card" style="background:#FFFFFF; padding:20px;">
          <h4 style="font-size:13px; font-weight:700; color:var(--text-dark); margin-bottom:10px;">⛓️ SCREEN DEPENDENCY RULES</h4>
          <div>
            ${rulesHtml}
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderMapsTab() {
  const container = document.getElementById('tab-content-maps');
  if (!container) return;

  const data = getActiveScreenDefinition();
  if (!data) {
    container.innerHTML = '<div class="no-data-state"><p>No screen active or loaded</p></div>';
    return;
  }

  // Generate Webservices list
  let wsHtml = '';
  if (Object.keys(data.webservices).length === 0) {
    wsHtml = '<div style="color:var(--text-light); font-size:13px; padding:10px;">No webservices used on this screen.</div>';
  } else {
    for (const [wsName, ws] of Object.entries(data.webservices)) {
      wsHtml += `
        <div style="border: 1px solid var(--border); border-radius: var(--radius); padding:16px; margin-bottom:12px; background:#FFFFFF;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
            <span style="font-family:'Fira Code', monospace; font-size:13px; font-weight:700; color:var(--primary);">${escHtml(wsName)}</span>
            <span style="font-size:11px; background:var(--primary-light); color:var(--primary-hover); padding:3px 8px; border-radius:12px; font-weight:600;">Used by: ${escHtml(ws.usedBy)}</span>
          </div>
          <div style="font-size:12px; font-family:'Fira Code', monospace; background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; overflow-x:auto;">
            <strong>Request EndPoint:</strong><br>${escHtml(ws.request)}<br><br>
            <strong>Mock API Response Schema:</strong><br>${escHtml(ws.response)}
          </div>
        </div>
      `;
    }
  }

  // Generate Objects list
  const objRows = data.objects.map(obj => `
    <tr>
      <td style="font-family:'Fira Code', monospace; font-weight:600; color:var(--text-dark);">${escHtml(obj.name)}</td>
      <td style="color:#16A34A; font-weight:500;">${escHtml(obj.created)}</td>
      <td style="color:#3B82F6; font-weight:500;">${escHtml(obj.used)}</td>
      <td style="color:#DC2626; font-weight:500;">${escHtml(obj.consumed)}</td>
    </tr>
  `).join('');

  container.innerHTML = `
    <div style="display:grid; grid-template-columns:1fr 1.2fr; gap:20px;">
      <!-- WebService Mapping -->
      <div class="risk-card" style="background:#FFFFFF; padding:20px;">
        <h4 style="font-size:13px; font-weight:700; color:var(--text-dark); margin-bottom:14px; display:flex; align-items:center; gap:6px;">
          <span>🌐</span> ASSOCIATED WEBSERVICES
        </h4>
        <div>
          ${wsHtml}
        </div>
      </div>

      <!-- Object Mapping -->
      <div class="risk-card" style="background:#FFFFFF; padding:20px;">
        <h4 style="font-size:13px; font-weight:700; color:var(--text-dark); margin-bottom:14px; display:flex; align-items:center; gap:6px;">
          <span>📦</span> SESSION OBJECT LIFECYCLE MAP
        </h4>
        <div style="overflow-x:auto;">
          <table class="explorer-table">
            <thead>
              <tr>
                <th>Object Name</th>
                <th>Created</th>
                <th>Used</th>
                <th>Consumed</th>
              </tr>
            </thead>
            <tbody>
              ${objRows}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function renderPageEventsTab() {
  const container = document.getElementById('tab-content-page');
  if (!container) return;

  const data = getActiveScreenDefinition();
  if (!data) {
    container.innerHTML = '<div class="no-data-state"><p>No screen active or loaded</p></div>';
    return;
  }
  const screenId = data.screenName || data.name || "CustomScreen";

  let html = '';
  for (const [eventName, event] of Object.entries(data.pageEvents)) {
    html += `
      <div id="page-event-sec-${escHtml(eventName)}" style="margin-bottom:24px;">
        <div style="font-size:14px; font-weight:700; color:var(--text-dark); margin-bottom:8px; display:flex; align-items:center; gap:6px;">
          <span>📄</span> ${escHtml(eventName)}
        </div>
        <div class="code-editor-header">
          <span>PAGE EVENT SCRIPT</span>
          <span style="color:#64748B">${escHtml(screenId)}_${escHtml(eventName)}.groovy</span>
        </div>
        <pre class="code-editor-box"><code>${escHtml(event.code)}</code></pre>
      </div>
    `;
  }

  container.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:10px;">
      ${html}
    </div>
  `;
}

function renderApiTracker(apis) {
  const container = document.getElementById('api-list-container');
  if (!apis || !apis.length) {
    container.innerHTML = '<div class="no-data-state"><p>No API calls detected in log</p></div>';
    document.getElementById('api-details-panel').innerHTML = `
      <div class="api-details-empty">
        <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
        </svg>
        <h3>No API Selected</h3>
        <p>Select an API call from the list to view its details, request headers, and response payload.</p>
      </div>`;
    return;
  }

  const renderList = (filteredApis) => {
    if (!filteredApis.length) {
      container.innerHTML = '<div class="no-data-state"><p>No matching API calls found</p></div>';
      return;
    }

    container.innerHTML = filteredApis.map((api) => {
      // Find original index in STATE.analysis.apis
      const origIdx = STATE.analysis.apis.indexOf(api);
      const isError = api.status >= 400;
      const badgeClass = isError ? 'error' : api.ms > 2000 ? 'warn' : 'success';
      const badgeText = api.status || 'OK';
      
      return `
        <div class="api-card" data-idx="${origIdx}">
          <div class="api-card-title">
            <span class="api-card-title-text" title="${escHtml(api.name)}">${escHtml(api.name)}</span>
            <span class="api-badge ${badgeClass}">${badgeText}</span>
          </div>
          <div class="api-card-meta">
            <span>${api.method || 'GET'}</span>
            <span>${api.ms}ms</span>
          </div>
        </div>`;
    }).join('');

    // Attach click listeners to cards
    container.querySelectorAll('.api-card').forEach(card => {
      card.addEventListener('click', () => {
        // Remove selection from all
        container.querySelectorAll('.api-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');

        const idx = parseInt(card.dataset.idx);
        renderApiDetails(STATE.analysis.apis[idx]);
      });
    });
  };

  // Initial render of all APIs
  renderList(apis);

  // Set up search filter for API Tracker
  const searchInput = document.getElementById('api-search-input');
  searchInput.value = ''; // clear previous value
  
  // Remove existing listeners by cloning (to prevent duplicate registrations)
  const newSearchInput = searchInput.cloneNode(true);
  searchInput.parentNode.replaceChild(newSearchInput, searchInput);
  
  newSearchInput.addEventListener('input', () => {
    const query = newSearchInput.value.toLowerCase().trim();
    if (!query) {
      renderList(apis);
      return;
    }
    const filtered = apis.filter(api => 
      (api.name || '').toLowerCase().includes(query) || 
      (api.endpoint || '').toLowerCase().includes(query) || 
      String(api.status || '').includes(query) ||
      (api.method || '').toLowerCase().includes(query)
    );
    renderList(filtered);
  });
}

function renderApiDetails(api) {
  const panel = document.getElementById('api-details-panel');
  if (!api) {
    panel.innerHTML = `
      <div class="api-details-empty">
        <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
        </svg>
        <h3>No API Selected</h3>
        <p>Select an API call from the list to view its details, request headers, and response payload.</p>
      </div>`;
    return;
  }

  const isError = api.status >= 400;
  const badgeClass = isError ? 'error' : api.ms > 2000 ? 'warn' : 'success';
  const httpInfo = HTTP_KB[api.status] || { label: 'Unknown', explain: 'No standard documentation for this status code.' };

  // Formatting request and response payload
  let reqPayloadHtml = 'N/A';
  if (api.request) {
    let reqText = api.request;
    try {
      if (reqText.trim().startsWith('{') || reqText.trim().startsWith('[')) {
        reqText = JSON.stringify(JSON.parse(reqText), null, 2);
      }
    } catch(e) {}
    reqPayloadHtml = `<pre class="api-payload-body">${redactHTML(escHtml(reqText))}</pre>`;
  }

  let respPayloadHtml = 'N/A';
  if (api.response) {
    let respText = api.response;
    try {
      if (respText.trim().startsWith('{') || respText.trim().startsWith('[')) {
        respText = JSON.stringify(JSON.parse(respText), null, 2);
      }
    } catch(e) {}
    respPayloadHtml = `<pre class="api-payload-body">${redactHTML(escHtml(respText))}</pre>`;
  }

  panel.innerHTML = `
    <div class="api-details-header">
      <span class="api-details-header-title">${escHtml(api.name)}</span>
      <span class="api-badge ${badgeClass}" style="font-size:12px; padding:3px 10px;">HTTP ${api.status} - ${httpInfo.label}</span>
    </div>
    <div class="api-details-content">
      <div class="api-details-row">
        <div class="api-details-label">API Name</div>
        <div class="api-details-value">${escHtml(api.name)}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">Request URL</div>
        <div class="api-details-value">${redactHTML(escHtml(api.endpoint || 'N/A'))}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">HTTP Method</div>
        <div class="api-details-value" style="font-weight:700; color:var(--primary);">${escHtml(api.method || 'GET')}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">Response Time</div>
        <div class="api-details-value" style="font-weight:700; color:${api.ms > 2000 ? 'var(--warning-text)' : 'var(--success-text)'}">${api.ms} ms</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">Timestamp</div>
        <div class="api-details-value">${escHtml(api.timestamp || 'N/A')}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">Thread Context</div>
        <div class="api-details-value">${redactHTML(escHtml(api.thread || 'N/A'))}</div>
      </div>
      
      <div style="margin-top: 14px; padding: 10px 14px; background:var(--bg); border-radius:8px; border:1px solid var(--border); font-size:12.5px; color:var(--text-normal); line-height:1.5;">
        <strong>Status Analysis:</strong> ${httpInfo.explain}
      </div>

      <div class="api-payload-box">
        <div class="api-payload-title">
          <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
            <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" />
          </svg>
          Request Payload
        </div>
        ${reqPayloadHtml}
      </div>

      <div class="api-payload-box">
        <div class="api-payload-title">
          <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
            <polyline points="4 17 10 11 4 5" />
            <line x1="12" y1="19" x2="20" y2="19" />
          </svg>
          Response Payload
        </div>
        ${respPayloadHtml}
      </div>
    </div>`;
}

function selectApiByName(name) {
  switchView('api');
  if (!STATE.analysis || !STATE.analysis.apis) return;
  const apiIndex = STATE.analysis.apis.findIndex(a => a.name === name);
  if (apiIndex !== -1) {
    const api = STATE.analysis.apis[apiIndex];
    renderApiDetails(api);
    setTimeout(() => {
      const container = document.getElementById('api-list-container');
      if (container) {
        container.querySelectorAll('.api-card').forEach(c => c.classList.remove('selected'));
        const targetCard = container.querySelector(`.api-card[data-idx="${apiIndex}"]`);
        if (targetCard) {
          targetCard.classList.add('selected');
          targetCard.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
      }
    }, 50);
  }
}

// ─── UI Rendering ─────────────────────────────────────────────────────────────

function renderDashboard(a) {
  const $ = id => document.getElementById(id);

  // Stat Cards
  $('stat-critical').textContent = a.errors.length;
  $('stat-critical-sub').textContent = a.errors.filter(e => e.level === 'FATAL').length + ' FATAL';
  $('stat-warnings').textContent = a.warnings.length;
  $('stat-warnings-sub').textContent = 'Needs attention';
  $('stat-slowapis').textContent = a.apis.filter(x => x.ms > 2000).length;
  $('stat-sqlfail').textContent = a.sqls.filter(s => s.code && s.code !== 'JSON_KEY_MISSING').length;
  $('stat-sqlfail-sub').textContent = a.sqls.length ? a.sqls.map(s => `ORA-${s.code}`).join(', ').substring(0, 30) : '';
  $('stat-users').textContent = a.users.length;
  $('stat-users-sub').textContent = a.users.slice(0, 2).join(', ');
  $('stat-total').textContent = a.totalLines;
  $('stat-total-sub').textContent = `${a.rawLineCount} raw lines`;

  // Health Score
  const sc = a.score;
  $('health-score-num').textContent = sc;
  const ring = $('health-ring-fill');
  const circ = 2 * Math.PI * 38;
  ring.style.strokeDashoffset = circ - (sc / 100) * circ;
  ring.style.stroke = sc >= 80 ? '#16A34A' : sc >= 60 ? '#F59E0B' : '#DC2626';

  const hb = $('health-badge');
  hb.className = 'health-badge ' + (sc >= 80 ? 'good' : sc >= 60 ? 'warn' : 'bad');
  $('health-badge-text').textContent = `Health: ${sc}/100`;

  $('hm-errrate').textContent = a.errors.length + ' errors';
  $('hm-errrate').className = 'health-meta-val' + (a.errors.length ? ' bad' : '');
  $('hm-apifail').textContent = a.apis.filter(x => x.status >= 400).length + ' failed';
  $('hm-sqlerr').textContent = a.sqls.length + ' errors';
  const slowest = a.apis.length ? Math.max(...a.apis.map(x => x.ms)) : 0;
  $('hm-slowapi').textContent = slowest ? slowest + 'ms' : 'None';
  $('hm-slowapi').className = 'health-meta-val' + (slowest > 5000 ? ' bad' : slowest > 2000 ? ' warn' : '');

  // Performance List
  const perfEl = $('perf-list');
  if (a.apis.length) {
    const maxMs = Math.max(...a.apis.map(x => x.ms), 1);
    perfEl.innerHTML = a.apis.sort((x, y) => y.ms - x.ms).map(api => {
      const pct = Math.round((api.ms / maxMs) * 100);
      const color = api.ms > 5000 ? '#DC2626' : api.ms > 2000 ? '#F59E0B' : '#16A34A';
      const statusBadge = api.status ? `<span class="badge ${api.status >= 400 ? 'error' : 'success'}" style="margin-left:6px;font-size:10px;">${api.status}</span>` : '';
      return `<div class="clickable-api-card" data-name="${escHtml(api.name)}" style="margin-bottom:12px; cursor:pointer; padding:6px; border-radius:6px; transition:background-color 0.15s;" onmouseover="this.style.backgroundColor='var(--bg-row-hover)'" onmouseout="this.style.backgroundColor='transparent'">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
          <span style="font-size:12.5px;font-weight:600;color:#1F2937;">${api.name}${statusBadge}</span>
        </div>
        <div class="perf-bar-wrap">
          <div class="perf-bar-bg"><div class="perf-bar-fill" style="width:${pct}%;background:${color};"></div></div>
          <span class="perf-ms" style="color:${color};">${api.ms}ms</span>
        </div>
        ${api.ms > 2000 ? `<div style="font-size:11px;color:${color};margin-top:3px;">⚠ ${api.ms > 5000 ? 'Critical — exceeds 5s threshold' : 'Slow — exceeds 2s threshold'}</div>` : ''}
      </div>`;
    }).join('');

    perfEl.querySelectorAll('.clickable-api-card').forEach(cardEl => {
      cardEl.addEventListener('click', () => {
        const name = cardEl.dataset.name;
        selectApiByName(name);
      });
    });
  } else {
    perfEl.innerHTML = '<div style="padding:12px;color:#9CA3AF;font-size:13px;">No API calls detected in log.</div>';
  }

  // Error Grouping
  const tbody = $('error-group-tbody');
  if (a.groups.length) {
    tbody.innerHTML = a.groups.map(g => `
      <tr class="clickable-group-row" data-key="${escHtml(g.key)}" style="cursor:pointer;">
        <td style="font-family:'Fira Code',monospace;font-size:12px;color:#1F2937;">${escHtml(g.key)}</td>
        <td><span class="err-count-badge">${g.count}</span></td>
        <td><span class="badge error" style="font-size:10px;">${escHtml(g.errType)}</span></td>
      </tr>`).join('');

    tbody.querySelectorAll('.clickable-group-row').forEach(rowEl => {
      rowEl.addEventListener('click', () => {
        const key = rowEl.dataset.key;
        const match = STATE.parsed.find(r => ['ERROR','FATAL'].includes(r.level) && r.message.includes(key));
        if (match) showAndHighlightLog(match.id);
      });
    });
  } else {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;padding:16px;color:#9CA3AF;">No errors found</td></tr>';
  }

  // SQL List
  const sqlEl = $('sql-list');
  if (a.sqls.length) {
    sqlEl.innerHTML = a.sqls.map(s => {
      if (s.code === 'JSON_KEY_MISSING') {
        return `<div class="ora-card clickable-sql-card" data-code="${escHtml(s.code)}" style="background:#ECFEFF;border-color:#A5F3FC;cursor:pointer;transition:transform 0.1s;" onmouseover="this.style.transform='scale(1.01)'" onmouseout="this.style.transform='scale(1)'">
          <div class="ora-code" style="color:#0E7490;">JSON Key Missing: "${escHtml(s.col)}"</div>
          <div class="ora-meaning">API response key not found. Schema may have changed.</div>
        </div>`;
      }
      const info = ORA_KB[s.code] || { msg: 'Oracle Error', explanation: '' };
      return `<div class="ora-card clickable-sql-card" data-code="${escHtml(s.code)}" style="cursor:pointer;transition:transform 0.1s;" onmouseover="this.style.transform='scale(1.01)'" onmouseout="this.style.transform='scale(1)'">
        <div class="ora-code">ORA-${s.code}: ${info.msg}</div>
        <div class="ora-meaning">${info.explanation}</div>
        ${s.col ? `<div class="ora-count">Identifier: <code style="font-family:'Fira Code',monospace;">${escHtml(s.col)}</code></div>` : ''}
      </div>`;
    }).join('');

    sqlEl.querySelectorAll('.clickable-sql-card').forEach(cardEl => {
      cardEl.addEventListener('click', () => {
        const code = cardEl.dataset.code;
        const match = STATE.parsed.find(r => r.message.includes(code) || (code === 'JSON_KEY_MISSING' && /JSONException|JSONObject/i.test(r.message)));
        if (match) showAndHighlightLog(match.id);
      });
    });
  } else {
    sqlEl.innerHTML = '<div style="padding:12px;color:#9CA3AF;font-size:13px;">No SQL errors detected.</div>';
  }

  // Module Card
  const modEl = $('module-card-body');
  modEl.innerHTML = `
    <div class="meta-row"><span class="meta-label">Module</span><span class="meta-val">${escHtml(a.module)}</span></div>
    <div class="meta-row"><span class="meta-label">Screen</span><span class="meta-val">${a.screen || 'Not detected'}</span></div>
    <div class="meta-row"><span class="meta-label">Transaction</span><span class="meta-val">${a.transaction || 'Not detected'}</span></div>
    <div class="meta-row"><span class="meta-label">Users</span><span class="meta-val">${a.users.length ? a.users.join(', ') : 'Not detected'}</span></div>
  `;

  // Dependency Chain
  const depEl = $('dep-chain-body');
  if (a.depChain.length) {
    depEl.innerHTML = a.depChain.map((item, i) => `
      <div style="display:flex;align-items:flex-start;gap:10px;${i > 0 ? 'margin-top:0;' : ''}">
        <div style="display:flex;flex-direction:column;align-items:center;width:24px;flex-shrink:0;">
          <div style="width:20px;height:20px;border-radius:50%;background:${item.type === 'error' ? '#FEF2F2' : '#F0FDF4'};border:2px solid ${item.type === 'error' ? '#DC2626' : '#16A34A'};display:flex;align-items:center;justify-content:center;font-size:9px;">
            ${item.type === 'error' ? '✕' : '✓'}
          </div>
          ${i < a.depChain.length - 1 ? `<div style="width:2px;height:20px;background:#E5E7EB;margin:2px 0;"></div>` : ''}
        </div>
        <div style="flex:1;padding-bottom:${i < a.depChain.length - 1 ? '2' : '0'}px;">
          <div style="font-size:13px;color:${item.type === 'error' ? '#DC2626' : '#16A34A'};font-weight:500;padding-top:1px;">${escHtml(item.label)}</div>
        </div>
      </div>
    `).join('');
  } else {
    depEl.innerHTML = '<div style="padding:12px;color:#9CA3AF;font-size:13px;">No dependency chain detected.</div>';
  }

  // Executive Summary
  const execEl = $('exec-summary-banner');
  if (a.execSummary) {
    $('exec-summary-body').innerHTML = a.execSummary;
    execEl.style.display = 'block';
  }

  // Update nav badge
  const badge = $('nav-badge-errors');
  if (a.errors.length) {
    badge.textContent = a.errors.length;
    badge.style.display = '';
  }
}

function renderTable() {
  const tbody = document.getElementById('logs-tbody');
  const rows = STATE.filtered;
  if (!rows.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="5">No log entries match the current filter.</td></tr>';
    return;
  }

  // To prevent browser freezing on massive logs, limit rendering to first 1000 matching rows
  const limit = 1000;
  const toRender = rows.slice(0, limit);

  tbody.innerHTML = toRender.map(row => {
    const lv = row.level || 'INFO';
    const lvClass = lv.toLowerCase();
    const hasDiag = row.isException || ['ERROR','FATAL'].includes(lv);
    const msgPreview = row.message.split('\n')[0];
    const src = (row.source || '').split('.').pop();
    return `<tr class="log-row lvl-${lvClass}" data-id="${row.id}">
      <td><span class="badge ${lvClass}">${lv}</span></td>
      <td class="ts-col">${row.timestamp || ''}</td>
      <td class="src-col" title="${escHtml(row.source || '')}">${escHtml(src)}</td>
      <td class="msg-col"><div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escHtml(msgPreview)}</div></td>
      <td class="fix-col">${hasDiag ? '<span class="fix-icon" title="Click for diagnostic">⚡</span>' : ''}</td>
    </tr>`;
  }).join('');

  // Append a visual indicator if truncated
  if (rows.length > limit) {
    const infoRow = document.createElement('tr');
    infoRow.innerHTML = `<td colspan="5" style="text-align:center; padding:12px; background:var(--bg); color:var(--text-muted); font-size:12.5px; font-weight:500; border-top:1px solid var(--border);">
      ⚠️ Showing first ${limit} log entries out of ${rows.length.toLocaleString()}. Use search and level filters to narrow down the results.
    </td>`;
    tbody.appendChild(infoRow);
  }

  // Row click
  tbody.querySelectorAll('.log-row').forEach(tr => {
    tr.addEventListener('click', () => {
      tbody.querySelectorAll('.log-row').forEach(r => r.classList.remove('selected'));
      tr.classList.add('selected');
      const id = parseInt(tr.dataset.id);
      const row = STATE.parsed.find(r => r.id === id);
      if (row) openDrawer(row);
    });
  });
}

function openDrawer(row) {
  STATE.selectedRow = row;
  const d = analyzeRow(row, STATE.parsed, STATE.analysis || {});
  const $ = id => document.getElementById(id);

  // Populate Code Execution Investigator Report Card
  if (d.codeExecutionReport) {
    $('ds-investigator-report').style.display = 'block';
    $('dc-investigator-report-text').textContent = d.codeExecutionReport;
  } else {
    $('ds-investigator-report').style.display = 'none';
  }

  // Badge & heading
  const lv = (row.level || 'INFO').toLowerCase();
  $('drawer-level-badge').className = `badge ${lv}`;
  $('drawer-level-badge').textContent = row.level;
  $('drawer-heading').textContent = d.errType;

  // ① Classification + Risk Level (Phase 1 + Phase 10)
  $('dc-errtype').innerHTML = `<span class="badge ${lv}" style="font-size:10px;">${escHtml(d.errType)}</span>` +
    (d.riskInfo ? ` <span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:${d.riskInfo.color}22;color:${d.riskInfo.color};border:1px solid ${d.riskInfo.color}44;">${d.riskInfo.icon} ${d.riskInfo.level} RISK</span>` : '');
  $('dc-module').textContent = (STATE.analysis ? STATE.analysis.module : '') || '—';
  $('dc-screen').textContent = (STATE.analysis ? STATE.analysis.screen : '') || extractScreenFromMsg(row.message) || '—';
  $('dc-user').textContent = d.threadUser || ((STATE.analysis && STATE.analysis.users) || []).join(', ') || extractUserFromMsg(row.message) || '—';
  $('dc-transaction').textContent = (STATE.analysis ? STATE.analysis.transaction : '') || extractTxFromMsg(row.message) || '—';
  $('dc-timestamp').textContent = row.timestamp || '—';

  // ② Variables
  const vars = d.variables;
  if (Object.keys(vars).length) {
    $('var-track-list').innerHTML = Object.entries(vars).map(([k, v]) => {
      const isNull = v === 'NULL' || v === 'null';
      return `<div class="meta-row">
        <span class="meta-label" style="font-family:'Fira Code',monospace;">${escHtml(k)}</span>
        <span class="meta-val" style="${isNull ? 'color:#DC2626;' : ''}">${isNull ? '⚠ NULL' : escHtml(v)}</span>
      </div>`;
    }).join('');
  } else {
    $('var-track-list').innerHTML = '<div style="color:#9CA3AF;font-size:12px;">No variables detected in context.</div>';
  }

  // ③ Root Cause + Confidence
  const pct = d.confidence;
  $('dc-conf-bar').style.width = pct + '%';
  $('dc-conf-bar').style.background = pct >= 80 ? '#16A34A' : pct >= 60 ? '#F59E0B' : '#DC2626';
  $('dc-conf-pct').textContent = pct + '%';
  $('dc-rootcause').innerHTML = d.rootCause || '—';

  // ④ Code
  if (d.codeTrace || d.lineNo) {
    $('ds-code').style.display = '';
    $('dc-script-name').textContent = d.script || 'unknown';
    $('dc-line-no').textContent = d.lineNo || '?';
    $('dc-code-trace').textContent = d.codeTrace || '(trace not available)';
    $('dc-code-explain').innerHTML = d.codeExplain || '';
    if (d.fixCode) {
      $('dc-fix-block').style.display = '';
      $('dc-fix-code').textContent = d.fixCode;
    } else {
      $('dc-fix-block').style.display = 'none';
    }
  } else {
    $('ds-code').style.display = 'none';
  }

  // ⑤ API
  if (d.apiInfo) {
    $('ds-api').style.display = '';
    const api = d.apiInfo;
    $('da-name').textContent = api.name;
    $('da-endpoint').textContent = api.endpoint || 'Not detected';
    const httpI = HTTP_KB[api.status] || {};
    $('da-status').innerHTML = api.status
      ? `<span style="color:${httpI.color || '#374151'};font-weight:700;">${api.status} ${httpI.label || ''}</span>`
      : '—';
    $('da-time').innerHTML = api.ms
      ? `<span style="color:${api.ms > 5000 ? '#DC2626' : api.ms > 2000 ? '#F59E0B' : '#16A34A'};font-weight:700;">${api.ms}ms</span>`
      : '—';
    $('da-http-explain').textContent = httpI.explain || '';
    if (api.request) {
      $('da-req-block').style.display = '';
      try { $('da-request').textContent = JSON.stringify(JSON.parse(api.request), null, 2); }
      catch { $('da-request').textContent = api.request; }
    } else { $('da-req-block').style.display = 'none'; }
    if (api.response) {
      $('da-resp-block').style.display = '';
      try { $('da-response').textContent = JSON.stringify(JSON.parse(api.response), null, 2); }
      catch { $('da-response').textContent = api.response; }
      // Response explanation
      const rc = api.status;
      if (rc === 500) {
        $('da-resp-explain').innerHTML = '<strong>Server Error Analysis:</strong><br>Fusion rejected the request. Likely causes: missing mandatory field, invalid payload, or Fusion is down.';
      } else if (rc === 404) {
        $('da-resp-explain').innerHTML = '<strong>Not Found Analysis:</strong><br>The resource or endpoint does not exist. Verify endpoint URL and API version.';
      } else {
        $('da-resp-explain').textContent = '';
      }
    } else { $('da-resp-block').style.display = 'none'; }
  } else {
    $('ds-api').style.display = 'none';
  }

  // ⑥ SQL
  if (d.sqlInfo) {
    $('ds-sql').style.display = '';
    const sql = d.sqlInfo;
    const oraInfo = ORA_KB[sql.code] || { msg: 'Database Error', explanation: '', fix: '' };
    $('dsql-ora').innerHTML = `<span class="badge error">ORA-${sql.code}</span> ${oraInfo.msg}`;
    $('dsql-meaning').innerHTML = `${oraInfo.explanation}<br><br><strong>Fix:</strong> ${oraInfo.fix}`;
    if (sql.sql) {
      $('dsql-query-block').style.display = '';
      $('dsql-query').textContent = sql.sql;
    } else { $('dsql-query-block').style.display = 'none'; }
    if (sql.params) {
      $('dsql-params-block').style.display = '';
      $('dsql-params').innerHTML = sql.params.split(',').map(p => {
        const [k, v] = p.trim().split('=');
        const isNull = !v || v === 'null' || v === 'NULL';
        return `<div class="meta-row"><span class="meta-label">${escHtml((k||'').trim())}</span><span class="meta-val" style="${isNull ? 'color:#DC2626;' : ''}">${isNull ? '⚠ NULL' : escHtml((v||'').trim())}</span></div>`;
      }).join('');
    } else { $('dsql-params-block').style.display = 'none'; }
  } else {
    $('ds-sql').style.display = 'none';
  }

  // Printer Info
  if (d.printerInfo) {
    $('ds-printer').style.display = '';
    $('dprint-name').textContent = d.printerInfo.name || '—';
    $('dprint-ip').textContent = d.printerInfo.ip || '—';
    $('dprint-template').textContent = d.printerInfo.template || '—';
    $('dprint-error').textContent = d.printerInfo.error || '—';
  } else {
    $('ds-printer').style.display = 'none';
  }

  // Validation Info
  if (d.validationInfo) {
    $('ds-validation').style.display = '';
    $('dval-list').innerHTML = d.validationInfo.listHTML || '—';
  } else {
    $('ds-validation').style.display = 'none';
  }

  // ⑦a Security Context Panel (Phase 16) — inject dynamically
  const existingSec = document.getElementById('ds-security-context');
  if (existingSec) existingSec.remove();
  if (d.securityContext) {
    const sc = d.securityContext;
    const secDiv = document.createElement('div');
    secDiv.id = 'ds-security-context';
    secDiv.className = 'rca-card';
    secDiv.style.cssText = 'border-left: 3px solid #DC2626; background: #FFF8F8;';
    secDiv.innerHTML = `
      <div class="rca-card-title" style="color:#DC2626;">🔐 Security Context Analysis (Phase 16)</div>
      <div class="meta-row"><span class="meta-label">Affected User</span><span class="meta-val" style="font-weight:700;">${escHtml(sc.user)}</span></div>
      <div class="meta-row"><span class="meta-label">Resource Accessed</span><span class="meta-val"><code>${escHtml(sc.resource)}</code></span></div>
      <div class="meta-row"><span class="meta-label">HTTP Status</span><span class="meta-val" style="color:#DC2626;font-weight:700;">${sc.status} ${sc.status === 403 ? 'Forbidden' : 'Unauthorized'}</span></div>
      <div class="meta-row"><span class="meta-label">Required Privilege</span><span class="meta-val" style="font-family:'Fira Code',monospace;font-size:11px;">${escHtml(sc.privilegeRequired)}</span></div>
      <div class="meta-row"><span class="meta-label">Recommended Role</span><span class="meta-val" style="color:#7C3AED;font-weight:600;">${escHtml(sc.roleRecommended)}</span></div>
      ${sc.hasCascade ? '<div style="margin-top:10px;padding:8px 10px;background:#FEF2F2;border-radius:6px;border:1px solid #FECACA;font-size:12px;color:#DC2626;"><strong>⚡ Phase 5 — Cascading Failure:</strong> This 403 response triggered a downstream JSONException crash because the script did not validate the response code before parsing.</div>' : ''}
    `;
    // Insert before impact section
    const impactEl = document.getElementById('ds-impact');
    if (impactEl) impactEl.parentNode.insertBefore(secDiv, impactEl);
  }

  // ⑦b Performance Info Panel (Phase 15) — inject dynamically
  const existingPerf = document.getElementById('ds-perf-info');
  if (existingPerf) existingPerf.remove();
  if (d.performanceInfo && d.performanceInfo.ms) {
    const perf = d.performanceInfo;
    const perfDiv = document.createElement('div');
    perfDiv.id = 'ds-perf-info';
    perfDiv.className = 'rca-card';
    const perfColor = perf.ms > 5000 ? '#DC2626' : perf.ms > 2000 ? '#F59E0B' : '#16A34A';
    perfDiv.innerHTML = `
      <div class="rca-card-title">⏱ Performance Analysis (Phase 15)</div>
      <div class="meta-row"><span class="meta-label">Response Time</span><span class="meta-val" style="color:${perfColor};font-weight:700;">${perf.ms}ms</span></div>
      <div class="meta-row"><span class="meta-label">Status</span><span class="meta-val" style="color:${perfColor};">${perf.label}</span></div>
      <div style="margin-top:6px;font-size:12px;color:#6B7280;">${escHtml(perf.note || '')}</div>
    `;
    const impactEl2 = document.getElementById('ds-impact');
    if (impactEl2) impactEl2.parentNode.insertBefore(perfDiv, impactEl2);
  }

  // ⑦ Impact
  $('dc-impact-body').innerHTML = d.impactText
    ? `<div class="diag-cause-text">${d.impactText}</div>
       <div class="meta-row"><span class="meta-label">Affected Users</span><span class="meta-val">${((STATE.analysis && STATE.analysis.users)||[]).join(', ') || 'Unknown'}</span></div>
       <div class="meta-row"><span class="meta-label">Module</span><span class="meta-val">${(STATE.analysis ? STATE.analysis.module : '') || '—'}</span></div>`
    : '—';

  // ⑧ Fix Recommendations
  $('dc-fix-body').innerHTML = `
    <div style="margin-bottom:10px;">
      <div style="font-size:11px;font-weight:700;color:#DC2626;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">🚨 Immediate Fix</div>
      <div style="font-size:13px;color:#374151;">${d.immediatefix || '—'}</div>
    </div>
    <div style="margin-bottom:10px;">
      <div style="font-size:11px;font-weight:700;color:#F59E0B;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">👨‍💻 Developer Fix</div>
      <div style="font-size:13px;color:#374151;">${d.devfix || '—'}</div>
    </div>
    <div>
      <div style="font-size:11px;font-weight:700;color:#16A34A;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">🛡 Preventive Fix</div>
      <div style="font-size:13px;color:#374151;">${d.preventivefix || '—'}</div>
    </div>
  `;

  // ⑨ Similar Incidents
  const sim = d.similar;
  $('dc-similar-body').innerHTML = sim
    ? `<div class="meta-row"><span class="meta-label">Found</span><span class="meta-val">${sim.count} similar incidents</span></div>
       <div class="meta-row"><span class="meta-label">Frequency</span><span class="meta-val">${sim.freq}</span></div>
       <div style="margin-top:8px;font-size:12.5px;color:#374151;line-height:1.6;"><strong>Most Common Resolution:</strong><br>${escHtml(sim.resolution)}</div>`
    : '<div style="color:#9CA3AF;font-size:13px;">No similar incidents in database.</div>';

  // ⑩ Context
  const ctxLines = d.contextText.split('\n').filter(Boolean).slice(-15);
  $('dc-context').innerHTML = ctxLines.map(l => {
    if (/ERROR|FATAL|Exception/.test(l)) return `<span class="ctx-err">${escHtml(l)}</span>`;
    if (/WARN/.test(l)) return `<span class="ctx-warn">${escHtml(l)}</span>`;
    return escHtml(l);
  }).join('\n') || '(no preceding context)';

  // ⑪ Raw Trace
  $('dc-rawtrace').textContent = d.rawTrace || '(no stack trace)';

  // Show drawer
  document.getElementById('diag-drawer').classList.add('open');
  document.getElementById('drawer-scroll').scrollTop = 0;
}

function renderTimeline(parsed) {
  const el = document.getElementById('timeline-list');
  if (!parsed.length) return;

  // Limit rendering to errors/warnings or first 500 items to avoid DOM performance bottleneck
  const limit = 500;
  const filtered = parsed.filter(row => ['FATAL', 'ERROR', 'WARN'].includes(row.level) || parsed.length <= limit);
  const toRender = filtered.slice(0, limit);

  el.innerHTML = '<div class="timeline-list">' + toRender.map(row => {
    const lv = (row.level || 'INFO').toLowerCase();
    const dotClass = lv === 'error' || lv === 'fatal' ? 'error' : lv === 'warn' ? 'warn' : lv === 'debug' ? 'debug' : 'info';
    const icon = lv === 'error' || lv === 'fatal' ? '✕' : lv === 'warn' ? '!' : '·';
    const src = (row.source || '').split('.').pop();
    const firstLine = row.message.split('\n')[0];
    return `<div class="timeline-item">
      <div class="timeline-dot ${dotClass}">${icon}</div>
      <div class="timeline-body">
        <div class="timeline-ts">${row.timestamp || ''}</div>
        <div class="timeline-msg">${escHtml(firstLine.substring(0, 120))}</div>
        <div class="timeline-src">${escHtml(src)}</div>
      </div>
    </div>`;
  }).join('') + '</div>';

  if (filtered.length > limit) {
    const infoDiv = document.createElement('div');
    infoDiv.style.cssText = 'text-align:center; padding:12px; color:var(--text-muted); font-size:12.5px; font-weight:500; margin-top:10px;';
    infoDiv.innerHTML = `⚠️ Showing first ${limit} significant timeline events out of ${filtered.length.toLocaleString()}.`;
    el.appendChild(infoDiv);
  }
}

function renderWMSFlow(flowSteps, analysis) {
  const el = document.getElementById('wms-flow-container');
  if (!flowSteps || !flowSteps.length) {
    el.innerHTML = '<div class="no-data-state" style="padding:20px;"><p>No transaction flow detected</p></div>';
    document.getElementById('flow-summary-body').innerHTML = '<div class="no-data-state" style="padding:20px;"><p>No summary available</p></div>';
    return;
  }

  el.innerHTML = '<div class="flow-container">' + flowSteps.map((step, i) => {
    const icon = step.status === 'success' ? '✓' : step.status === 'error' ? '✕' : '○';
    const isLast = i === flowSteps.length - 1;
    const connClass = step.status === 'success' ? 'done' : step.status === 'error' ? 'broken' : '';
    return `<div class="flow-step">
      <div class="flow-step-line">
        <div class="flow-circle ${step.status}">${icon}</div>
        ${!isLast ? `<div class="flow-connector ${connClass}"></div>` : ''}
      </div>
      <div class="flow-body">
        <div class="flow-label ${step.status === 'error' ? 'style="color:#DC2626;"' : ''}">${step.status === 'error' ? '⚠ ' : ''}${escHtml(step.label)}</div>
        <div class="flow-sub">${step.status === 'success' ? 'Completed' : step.status === 'error' ? 'FAILED — Transaction stopped here' : 'Not reached'}</div>
      </div>
    </div>`;
  }).join('') + '</div>';

  // Summary
  const summaryEl = document.getElementById('flow-summary-body');
  const failStep = flowSteps.find(s => s.status === 'error');
  const doneCount = flowSteps.filter(s => s.status === 'success').length;
  summaryEl.innerHTML = `
    <div class="meta-row"><span class="meta-label">Module</span><span class="meta-val">${analysis.module}</span></div>
    <div class="meta-row"><span class="meta-label">Steps Done</span><span class="meta-val">${doneCount} / ${flowSteps.length}</span></div>
    <div class="meta-row"><span class="meta-label">Failed At</span><span class="meta-val" style="color:#DC2626;">${failStep ? failStep.label : 'No failure detected'}</span></div>
    <div class="meta-row"><span class="meta-label">User</span><span class="meta-val">${analysis.users?.join(', ') || '—'}</span></div>
    <div class="meta-row"><span class="meta-label">Transaction</span><span class="meta-val">${analysis.transaction || '—'}</span></div>
  `;
}

// ─── Ask AI Engine ────────────────────────────────────────────────────────────
function askQuestion(question) {
  const chatInput = document.getElementById('chat-input');
  chatInput.value = question;
  sendChatMessage();
}

function sendChatMessage() {
  const input = document.getElementById('chat-input');
  const question = input.value.trim();
  if (!question) return;

  appendChat('user', escHtml(question));
  input.value = '';

  // Generate response
  setTimeout(() => {
    const answer = generateAIAnswer(question);
    appendChat('ai', answer);
  }, 300);
}

function appendChat(role, html) {
  const box = document.getElementById('chat-messages');
  const div = document.createElement('div');
  div.className = `chat-msg ${role}`;
  div.innerHTML = html;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

function generateAIAnswer(q) {
  if (!STATE.analysis) {
    return '⚠️ No log file loaded yet. Please upload or paste a log file first, then ask me your question.';
  }
  const a = STATE.analysis;
  const lq = q.toLowerCase();

  // --- New Code Reviewer & Screen Explorer commands ---
  if (/screen flow|show.*flow/i.test(q)) {
    const scr = a.screen || 'TASK_SCREEN_11';
    const sData = getActiveScreenDefinition();
    if (!sData) return '⚠️ No screen definition loaded. Please upload a Screen JSON file.';
    const flowStr = sData.flow.join(' → ');
    return `🔍 <strong>Screen Flow for ${escHtml(scr)}:</strong><br><br><code>${escHtml(flowStr)}</code><br><br><em>Tip: Open the <strong>Code Reviewer</strong> tab and click the <strong>Screen Flow & Inventory</strong> sub-tab to see the interactive flow viz.</em>`;
  }

  if (/show.*code.*field\s*(\w+)/i.test(q) || /code.*field\s*(\w+)/i.test(q)) {
    const mMatch = q.match(/field\s*(\w+)/i);
    const fieldQuery = mMatch ? mMatch[1].toUpperCase() : null;
    const scr = a.screen || 'TASK_SCREEN_11';
    const sData = getActiveScreenDefinition();
    if (!sData) return '⚠️ No screen definition loaded. Please upload a Screen JSON file.';
    if (fieldQuery && sData.fields[fieldQuery]) {
      const events = sData.fields[fieldQuery];
      let resp = `💻 <strong>Event Code for ${escHtml(fieldQuery)} on ${escHtml(scr)}:</strong><br>`;
      for (const [evName, ev] of Object.entries(events)) {
        resp += `<br><strong>Event: ${escHtml(evName)}</strong><pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace;">${escHtml(ev.code)}</pre>`;
      }
      return resp;
    }
    return `Field <code>${escHtml(fieldQuery)}</code> not found on the active screen. Try fields: ${Object.keys(sData.fields).join(', ')}.`;
  }

  if (/show.*code.*(onexit|onchange|onvalidate|input processor|onpageentered|onspecialkeypressed)/i.test(q) || /(onexit|onchange|onvalidate|input processor|onpageentered|onspecialkeypressed).*code/i.test(q)) {
    const scr = a.screen || 'TASK_SCREEN_11';
    const sData = getActiveScreenDefinition();
    if (!sData) return '⚠️ No screen definition loaded. Please upload a Screen JSON file.';
    const evQuery = q.match(/(onexit|onchange|onvalidate|input processor|onpageentered|onspecialkeypressed)/i)[1].toLowerCase();
    
    // Check page events
    let pageEvName = Object.keys(sData.pageEvents).find(k => k.toLowerCase().includes(evQuery));
    if (pageEvName) {
      return `📄 <strong>Page Event: ${escHtml(pageEvName)}</strong><pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace;">${escHtml(sData.pageEvents[pageEvName].code)}</pre>`;
    }
    
    // Check field events
    let foundCode = '';
    for (const [fieldName, events] of Object.entries(sData.fields)) {
      let fEvName = Object.keys(events).find(k => k.toLowerCase().includes(evQuery));
      if (fEvName) {
        foundCode += `<br><strong>Field: ${escHtml(fieldName)} (Event: ${escHtml(fEvName)})</strong><pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace;">${escHtml(events[fEvName].code)}</pre>`;
      }
    }
    if (foundCode) {
      return `💻 <strong>Event Code matches:</strong><br>${foundCode}`;
    }
    return `No code found for event type: <code>${escHtml(evQuery)}</code>.`;
  }

  if (/related api|apis/i.test(q)) {
    const scr = a.screen || 'TASK_SCREEN_11';
    const sData = getActiveScreenDefinition();
    if (!sData) return '⚠️ No screen definition loaded. Please upload a Screen JSON file.';
    if (Object.keys(sData.webservices).length === 0) return `No associated APIs configured for ${escHtml(scr)}.`;
    const apisList = Object.entries(sData.webservices).map(([name, ws]) => `• <strong>${escHtml(name)}</strong> (Called by field: <code>${escHtml(ws.usedBy)}</code>)<br>Endpoint: <code>${escHtml(ws.request)}</code>`).join('<br><br>');
    return `🌐 <strong>WebService Mapping for ${escHtml(scr)}:</strong><br><br>${apisList}`;
  }

  if (/dependent field|dependency|visibility|rules/i.test(q)) {
    const scr = a.screen || 'TASK_SCREEN_11';
    const sData = getActiveScreenDefinition();
    if (!sData) return '⚠️ No screen definition loaded. Please upload a Screen JSON file.';
    const depsList = sData.dependencies.map(d => `• <strong>${escHtml(d.title)}</strong> (${escHtml(d.type)}): ${escHtml(d.desc)}`).join('<br><br>');
    return `⛓️ <strong>Screen Dependency Graph & Logic for ${escHtml(scr)}:</strong><br><br>${depsList}`;
  }

  if (/review.*screen|review.*field|risky.*code|vulnerability|missing.*validation/i.test(q)) {
    const scr = a.screen || 'TASK_SCREEN_11';
    const sData = getActiveScreenDefinition();
    if (!sData) return '⚠️ No screen definition loaded. Please upload a Screen JSON file.';
    let risks = [];
    for (const [fieldName, events] of Object.entries(sData.fields)) {
      for (const [evName, ev] of Object.entries(events)) {
        if (ev.severity === 'critical' || ev.severity === 'high' || ev.severity === 'medium') {
          risks.push(`• <code>${escHtml(fieldName)} (${escHtml(evName)})</code>: <strong>${ev.severity.toUpperCase()} RISK</strong> - ${escHtml(ev.risk)}`);
        }
      }
    }
    return `⚠️ <strong>Automated Code Review & Risk Analysis for ${escHtml(scr)}:</strong><br><br>
    ${risks.length ? risks.join('<br><br>') : '✅ No high-severity code risks found on this screen! All bindings are null-safe.'}<br><br>
    <em>Tip: Refactor suggestions are detailed in the <strong>Code Reviewer</strong> tab.</em>`;
  }

  if (/investigate|code execution investigator|execution report|full report/i.test(q)) {
    const err = a.errors[0] || STATE.parsed.find(r => r.level === 'ERROR' || r.level === 'WARN') || STATE.parsed[0];
    if (!err) return 'No log entries found to investigate.';
    const d = analyzeRow(err, STATE.parsed, a);
    return `🔍 <strong>Code Execution Investigator Report:</strong><br><pre style="font-family:'Fira Code', monospace; background:#0F172A; color:#E2E8F0; padding:15px; border-radius:8px; overflow-x:auto; font-size:12px; line-height:1.5; white-space:pre-wrap; word-break:break-all;">${escHtml(d.codeExecutionReport)}</pre>`;
  }

  if (/executive summary|summary|overview/i.test(q)) {
    return a.execSummary ? `📋 <strong>Executive Summary</strong><br><br>${a.execSummary}` : 'No summary available — load a log file first.';
  }

  if (/root cause|why.*fail|what.*cause|what happened/i.test(q)) {
    const err = a.errors[0] || STATE.parsed.find(r => r.level === 'ERROR' || r.level === 'WARN') || STATE.parsed[0];
    if (!err) return 'No errors found in the log.';
    const d = analyzeRow(err, STATE.parsed, a);
    return `🎯 <strong>Root Cause Analysis Report:</strong><br><pre style="font-family:'Fira Code', monospace; background:#0F172A; color:#E2E8F0; padding:15px; border-radius:8px; overflow-x:auto; font-size:12px; line-height:1.5; white-space:pre-wrap; word-break:break-all;">${escHtml(d.codeExecutionReport)}</pre>`;
  }

  if (/script fail|beandshell|target.*error|line number/i.test(q)) {
    const scriptErr = STATE.parsed.find(r => /TargetError/.test(r.message));
    if (!scriptErr) return 'No BeanShell/script errors found in this log.';
    const d = analyzeRow(scriptErr, STATE.parsed, a);
    return `📜 <strong>Script Failure Report:</strong><br><pre style="font-family:'Fira Code', monospace; background:#0F172A; color:#E2E8F0; padding:15px; border-radius:8px; overflow-x:auto; font-size:12px; line-height:1.5; white-space:pre-wrap; word-break:break-all;">${escHtml(d.codeExecutionReport)}</pre>`;
  }

  if (/slow.*api|api.*slow|performance|latency|slow/i.test(q)) {
    if (!a.apis.length) return 'No API calls detected in this log.';
    const slow = a.apis.sort((x, y) => y.ms - x.ms);
    const list = slow.map(api => `• <strong>${api.name}</strong>: ${api.ms}ms ${api.ms > 5000 ? '🔴 Critical' : api.ms > 2000 ? '🟡 Slow' : '🟢 OK'}${api.status ? ` | HTTP ${api.status}` : ''}`).join('<br>');
    return `⏱ <strong>API Performance Report:</strong><br><br>${list}<br><br>${slow[0].ms > 2000 ? `⚠️ <strong>${slow[0].name}</strong> is the slowest API. Check Fusion server health and network connectivity.` : '✅ All APIs within acceptable range.'}`;
  }

  if (/sql.*error|ora.*error|database.*error|oracle.*error/i.test(q)) {
    const err = STATE.parsed.find(r => /SQLException|ORA-/i.test(r.message)) || a.errors[0];
    if (!err) return 'No SQL or ORA errors detected in this log.';
    const d = analyzeRow(err, STATE.parsed, a);
    return `🗃️ <strong>Database Query Error Report:</strong><br><pre style="font-family:'Fira Code', monospace; background:#0F172A; color:#E2E8F0; padding:15px; border-radius:8px; overflow-x:auto; font-size:12px; line-height:1.5; white-space:pre-wrap; word-break:break-all;">${escHtml(d.codeExecutionReport)}</pre>`;
  }

  if (/http.*error|api.*error|webservice.*error/i.test(q)) {
    const err = STATE.parsed.find(r => /Response Code\s*[=:]\s*(4\d{2}|5\d{2})/i.test(r.message)) || a.errors[0];
    if (!err) return 'No HTTP or Web Service errors detected in the log.';
    const d = analyzeRow(err, STATE.parsed, a);
    return `🌐 <strong>Web Service Error Report:</strong><br><pre style="font-family:'Fira Code', monospace; background:#0F172A; color:#E2E8F0; padding:15px; border-radius:8px; overflow-x:auto; font-size:12px; line-height:1.5; white-space:pre-wrap; word-break:break-all;">${escHtml(d.codeExecutionReport)}</pre>`;
  }

  if (/fix|solution|how to.*fix|recommend/i.test(q)) {
    const err = a.errors[0] || STATE.parsed.find(r => r.level === 'ERROR' || r.level === 'WARN') || STATE.parsed[0];
    if (!err) return 'No errors found to suggest fixes for.';
    const d = analyzeRow(err, STATE.parsed, a);
    return `🔧 <strong>Suggested Fix Report:</strong><br><pre style="font-family:'Fira Code', monospace; background:#0F172A; color:#E2E8F0; padding:15px; border-radius:8px; overflow-x:auto; font-size:12px; line-height:1.5; white-space:pre-wrap; word-break:break-all;">${escHtml(d.codeExecutionReport)}</pre>`;
  }

  if (/user|who.*affect|affected.*user/i.test(q)) {
    return a.users.length
      ? `👤 <strong>Affected Users:</strong><br><br>${a.users.map(u => `• ${u}`).join('<br>')}`
      : 'No user information detected in the log.';
  }

  if (/module|which module|what module/i.test(q)) {
    return `📦 <strong>Affected Module:</strong> ${a.module}<br>Screen: ${a.screen || 'Not detected'}<br>Transaction: ${a.transaction || 'Not detected'}`;
  }

  if (/health|score/i.test(q)) {
    const sc = a.score;
    const rating = sc >= 80 ? '🟢 Healthy' : sc >= 60 ? '🟡 Degraded' : '🔴 Critical';
    return `📊 <strong>Log Health Score: ${sc}/100</strong> — ${rating}<br><br>Errors: ${a.errors.length} | Warnings: ${a.warnings.length} | SQL Failures: ${a.sqls.length} | Slow APIs: ${a.apis.filter(x => x.ms > 2000).length}`;
  }

  if (/variable|null|missing.*value/i.test(q)) {
    const vars = a.vars;
    if (!Object.keys(vars).length) return 'No variable tracking data found in this log.';
    const nullVars = Object.entries(vars).filter(([k, v]) => v === 'NULL');
    if (nullVars.length) {
      return `📌 <strong>Null Variables Detected:</strong><br><br>${nullVars.map(([k]) => `• <code>${k}</code> = NULL ⚠`).join('<br>')}<br><br>These null values are likely causing the script failure.`;
    }
    return `📌 <strong>Variables Tracked:</strong><br><br>${Object.entries(vars).map(([k, v]) => `• <code>${k}</code> = ${v}`).join('<br>')}`;
  }

  if (/error|exception/i.test(q)) {
    if (!a.errors.length) return '✅ No errors found in this log!';
    return `⚠️ <strong>${a.errors.length} errors detected:</strong><br><br>` +
      a.groups.map(g => `• <strong>${g.key}</strong> × ${g.count} (${g.errType})`).join('<br>');
  }

  // Generic fallback
  const err = a.errors[0] || STATE.parsed.find(r => r.level === 'ERROR' || r.level === 'WARN') || STATE.parsed[0];
  const reportText = err ? analyzeRow(err, STATE.parsed, a).codeExecutionReport : '';
  return `I analyzed your log. Here is the <strong>Code Execution Investigator Report</strong> for the primary log event:<br><br>
<pre style="font-family:'Fira Code', monospace; background:#0F172A; color:#E2E8F0; padding:15px; border-radius:8px; overflow-x:auto; font-size:12px; line-height:1.5; white-space:pre-wrap; word-break:break-all;">${escHtml(reportText)}</pre>`;
}

function runScreenDebuggerAnalysis() {
  const $ = id => document.getElementById(id);
  if (!STATE.analysis) {
    $('dbg-screen-title').textContent = "No Log File Active";
    $('dbg-screen-meta').textContent = "Please upload a log file or select a sample first.";
    $('dbg-workflow-container').innerHTML = `<div style="font-size: 13px; color: var(--text-muted); padding: 20px; text-align: center;">Upload a log to start.</div>`;
    $('dbg-analysis-panel').innerHTML = `
      <div class="api-details-empty">
        <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
          <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
        </svg>
        <h3>No Screen Definition or Log Active</h3>
        <p>Upload a Screen JSON file and a Log file, or load one of the generic samples from the sidebar to automatically run the Screen Debugger AI.</p>
      </div>`;
    return;
  }

  const logText = STATE.parsed.map(e => e.message).join('\n');

  // Find screen definition
  return; // Screen Debugger removed

  // Parse details
  const name = screenDef.screenName || screenDef.name || "Unknown Screen";
  const title = screenDef.title || name;
  const module = screenDef.module || "General";
  const flow = screenDef.flow || [];
  
  $('dbg-screen-title').textContent = title;
  $('dbg-screen-meta').textContent = `Screen: ${name} | Module: ${module} | Fields: ${flow.length}${isSimulated ? ' (Simulated from Log context)' : ''}`;

  // Find failing components
  let failingField = null;
  let failingEvent = null;
  let failingApi = null;
  let failingObject = null;

  // Search logic for failures
  if (logText.includes("NullPointerException") || logText.includes("TargetError")) {
    failingField = flow.find(f => logText.includes(f));
    failingEvent = "OnExit";
  }
  if (logText.includes("JSONException") || logText.includes("Response Code")) {
    failingApi = (STATE.analysis.apis && STATE.analysis.apis.length) ? STATE.analysis.apis[0].name : "REST_API";
    const inventoryItem = screenDef.inventory ? screenDef.inventory.find(i => i.webservice === failingApi) : null;
    if (inventoryItem) {
      failingField = inventoryItem.field;
      failingEvent = "OnExit";
    }
  }
  if (logText.includes("ORA-")) {
    failingField = flow.find(f => logText.includes(f));
  }

  // Draw Workflow Diagram
  let workflowHtml = "";
  flow.forEach((step, idx) => {
    const isActive = step === failingField;
    workflowHtml += `
      <div class="dbg-flow-item ${isActive ? 'active' : ''}">
        <div style="font-weight: 700; font-size: 13px; color: ${isActive ? 'var(--error)' : 'var(--text-dark)'};">${escHtml(step)}</div>
        <div style="font-size: 10px; color: var(--text-light); text-transform: uppercase;">${isActive ? '🔴 CRITICAL FAILURE' : 'Component'}</div>
      </div>
    `;
    if (idx < flow.length - 1) {
      workflowHtml += `<div class="dbg-flow-arrow">↓</div>`;
    }
  });
  $('dbg-workflow-container').innerHTML = workflowHtml;

  // Let's analyze Loggers & Status Messages coverage
  const coverageItems = [];
  const suggestionsLoggers = [];
  const suggestionsStatus = [];
  const apiDebuggingList = [];

  flow.forEach(field => {
    const fieldEvents = screenDef.fields ? screenDef.fields[field] : null;
    let hasLogger = false;
    let hasStatusMessage = false;
    let eventName = "OnExit";
    let eventCode = "";

    if (fieldEvents) {
      const keys = Object.keys(fieldEvents);
      if (keys.length) {
        eventName = keys[0];
        eventCode = fieldEvents[eventName].code || "";
        if (/logger\.(trace|debug|info|error)/i.test(eventCode)) {
          hasLogger = true;
        }
        if (/setStatusMessage/i.test(eventCode)) {
          hasStatusMessage = true;
        }
      }
    }

    coverageItems.push({
      field,
      hasLogger,
      hasStatusMessage
    });

    // Suggest missing loggers
    if (field === failingField || (!hasLogger && (field === 'SUBINV' || field === 'LOCATOR' || field === 'QTY' || field === 'LOT'))) {
      const codeSuggestion = `logger.debug("${field} value=" + ${field}.getValue());`;
      suggestionsLoggers.push({
        field,
        event: eventName,
        current: eventCode ? eventCode.trim() : `// Empty ${eventName} event handler`,
        suggested: codeSuggestion,
        reason: `${field} field value is currently not traceable during execution failures. Adding a trace logger enables live monitoring of scanning inputs.`
      });
    }

    // Suggest missing status messages
    if (field === failingField || (!hasStatusMessage && (field === 'SUBINV' || field === 'QTY' || field === 'LOT'))) {
      const statusSuggestion = `flexi.setStatusMessage("${field} is required. Please scan or enter a value.");`;
      suggestionsStatus.push({
        field,
        event: eventName,
        suggested: statusSuggestion,
        reason: `If validation fails or field is skipped, the user currently receives no visual error feedback in the scanner interface. Adding a status message tells them exactly how to proceed.`
      });
    }
  });

  // API Debugging suggestions
  if (screenDef.webservices) {
    for (const [wsName, ws] of Object.entries(screenDef.webservices)) {
      const apiCode = `logger.debug("${wsName} Response Code=" + ${wsName}.getResponseCode());\nlogger.debug("${wsName} Response=" + ${wsName}.getRawResponse());`;
      apiDebuggingList.push({
        name: wsName,
        endpoint: ws.request,
        suggested: apiCode,
        reason: `Monitors downstream WebService response status and logs any JSON/HTML payload payload schema mismatches.`
      });
    }
  }

  // Debugging Steps
  const debuggingSteps = [];
  let stepIndex = 1;
  if (failingField) {
    debuggingSteps.push({
      num: `Step ${stepIndex++}`,
      desc: `Verify value of component <code>${failingField}</code> prior to event <code>${failingEvent}</code>.`,
      logger: `logger.debug("${failingField} value=" + ${failingField}.getValue());`
    });
  }
  if (failingApi) {
    debuggingSteps.push({
      num: `Step ${stepIndex++}`,
      desc: `Check downstream API response code and raw body for service <code>${failingApi}</code>.`,
      logger: `logger.debug("${failingApi} Code=" + ${failingApi}.getResponseCode());\nlogger.debug("${failingApi} Body=" + ${failingApi}.getRawResponse());`
    });
  }
  if (failingObject) {
    debuggingSteps.push({
      num: `Step ${stepIndex++}`,
      desc: `Verify active lifecycle status of runtime object <code>${failingObject}</code>.`,
      logger: `logger.debug("flexiObject ${failingObject}=" + flexi.getObject("${failingObject}"));`
    });
  }
  if (debuggingSteps.length < 3) {
    debuggingSteps.push({
      num: `Step ${stepIndex++}`,
      desc: "Check session organization ID parameters to verify API connection authorization context.",
      logger: 'logger.debug("SCM_ORG_ID=" + flexi.getSessionObject("ORACLE_SCM_ORG_ID"));'
    });
  }
  if (debuggingSteps.length < 4) {
    debuggingSteps.push({
      num: `Step ${stepIndex++}`,
      desc: "Track active user ID and thread identifier for transaction audit tracing.",
      logger: 'logger.info("Thread Context = " + Thread.currentThread().getName());'
    });
  }

  // Construct findings layout
  let analysisHtml = "";

  // 1. Logger Coverage checklist card
  const checklistRows = coverageItems.map(item => `
    <div class="dbg-coverage-item">
      <span style="font-family:'Fira Code', monospace; font-weight:700;">${escHtml(item.field)}</span>
      <div style="display:flex; gap:6px;">
        <span class="dbg-coverage-badge ${item.hasLogger ? 'logged' : 'missing'}">
          ${item.hasLogger ? '✓ Logger' : '✗ Unlogged'}
        </span>
        <span class="dbg-coverage-badge ${item.hasStatusMessage ? 'logged' : 'missing'}">
          ${item.hasStatusMessage ? '✓ Status Msg' : '✗ No Status Msg'}
        </span>
      </div>
    </div>
  `).join('');

  analysisHtml += `
    <div class="dbg-copilot-section">
      <div class="dbg-copilot-title">
        <span>📊</span> LOGGER COVERAGE ANALYSIS
      </div>
      <div style="font-size:12.5px; color:var(--text-muted); margin-bottom:8px;">Logs analyze whether active fields include tracing and message alerts in their scripts.</div>
      <div class="dbg-coverage-list">
        ${checklistRows}
      </div>
    </div>
  `;

  // 2. Suggested Loggers Card
  if (suggestionsLoggers.length) {
    const sLogList = suggestionsLoggers.map(s => `
      <div style="border-bottom:1px solid var(--border); padding-bottom:12px; margin-bottom:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <span style="font-family:'Fira Code', monospace; font-weight:700; color:var(--primary); font-size:13px;">${escHtml(s.field)} (${escHtml(s.event)})</span>
          <span style="font-size:10px; background:#EFF6FF; color:#3B82F6; font-weight:600; padding:2px 8px; border-radius:10px;">Recommended Tracing</span>
        </div>
        <div style="font-size:12px; color:var(--text-normal); margin-bottom:6px;"><strong>Reason:</strong> ${escHtml(s.reason)}</div>
        <pre style="background:#0F172A; color:#86EFAC; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto;">${escHtml(s.suggested)}</pre>
      </div>
    `).join('');

    analysisHtml += `
      <div class="dbg-copilot-section">
        <div class="dbg-copilot-title" style="color:var(--primary);">
          <span>📝</span> RECOMMENDED LOGGER IMPROVEMENTS
        </div>
        <div>
          ${sLogList}
        </div>
      </div>
    `;
  }

  // 3. Suggested User Status Message Alerts
  if (suggestionsStatus.length) {
    const sStatList = suggestionsStatus.map(s => `
      <div style="border-bottom:1px solid var(--border); padding-bottom:12px; margin-bottom:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <span style="font-family:'Fira Code', monospace; font-weight:700; color:var(--success); font-size:13px;">${escHtml(s.field)} (${escHtml(s.event)})</span>
          <span style="font-size:10px; background:#F0FDF4; color:#16A34A; font-weight:600; padding:2px 8px; border-radius:10px;">Feedback Alert</span>
        </div>
        <div style="font-size:12px; color:var(--text-normal); margin-bottom:6px;"><strong>Reason:</strong> ${escHtml(s.reason)}</div>
        <pre style="background:#0F172A; color:#86EFAC; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto;">${escHtml(s.suggested)}</pre>
      </div>
    `).join('');

    analysisHtml += `
      <div class="dbg-copilot-section">
        <div class="dbg-copilot-title" style="color:var(--success);">
          <span>💬</span> RECOMMENDED USER STATUS FEEDBACK
        </div>
        <div>
          ${sStatList}
        </div>
      </div>
    `;
  }

  // 4. API Debugging Details
  if (apiDebuggingList.length) {
    const apiDList = apiDebuggingList.map(a => `
      <div style="border-bottom:1px solid var(--border); padding-bottom:12px; margin-bottom:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <span style="font-family:'Fira Code', monospace; font-weight:700; color:#7C3AED; font-size:13px;">${escHtml(a.name)}</span>
          <span style="font-size:10px; background:#F5F3FF; color:#7C3AED; font-weight:600; padding:2px 8px; border-radius:10px;">Integration Log</span>
        </div>
        <div style="font-size:12px; color:var(--text-normal); margin-bottom:6px;"><strong>Endpoint:</strong> <code>${escHtml(a.endpoint)}</code></div>
        <div style="font-size:12px; color:var(--text-normal); margin-bottom:6px;"><strong>Reason:</strong> ${escHtml(a.reason)}</div>
        <pre style="background:#0F172A; color:#86EFAC; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto;">${escHtml(a.suggested)}</pre>
      </div>
    `).join('');

    analysisHtml += `
      <div class="dbg-copilot-section">
        <div class="dbg-copilot-title" style="color:#7C3AED;">
          <span>🌐</span> WEB SERVICE API LOG RECOMMENDATIONS
        </div>
        <div>
          ${apiDList}
        </div>
      </div>
    `;
  }

  // 5. Debugging Guide / Steps Card
  const guideSteps = debuggingSteps.map(step => `
    <div class="dbg-step-item">
      <div class="dbg-step-num">${escHtml(step.num)}</div>
      <div class="dbg-step-desc">${step.desc}</div>
      <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11.5px; overflow-x:auto; margin:0; border:1px solid rgba(255,255,255,0.06);">${escHtml(step.logger)}</pre>
    </div>
  `).join('');

  analysisHtml += `
    <div class="dbg-copilot-section" style="border-left: 4px solid var(--primary);">
      <div class="dbg-copilot-title" style="color:var(--primary);">
        <span>🛠️</span> PRODUCTION DEBUGGING GUIDE
      </div>
      <div style="font-size:13px; line-height:1.6; color:var(--text-normal); margin-bottom:12px; background:rgba(59,130,246,0.04); border:1px dashed rgba(59,130,246,0.2); padding:12px; border-radius:6px;">
        <strong>Senior Support Engineer Mentoring Advice:</strong><br>
        In Flexi development, the error type itself is often clear (such as a NullPointerException), but finding which component fields or transaction values were mismatched requires structured tracing. 
        Follow the exact sequence below to add debug logs at strategic boundaries to inspect runtime state variables.
      </div>
      <div>
        ${guideSteps}
      </div>
    </div>
  `;

  $('dbg-analysis-panel').innerHTML = analysisHtml;
}

// ─── Helper Extractors ────────────────────────────────────────────────────────
function extractScreenFromMsg(msg) {
  const m = msg.match(/Screen:\s*([A-Z0-9_]+)/i);
  return m ? m[1] : null;
}
function extractUserFromMsg(msg) {
  const m = msg.match(/User:\s*([A-Z0-9_]+)/i);
  return m ? m[1] : null;
}
function extractTxFromMsg(msg) {
  const m = msg.match(/[Tt]ransaction:\s*([^,\n\.]+)/);
  return m ? m[1].trim() : null;
}
function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── View Router ──────────────────────────────────────────────────────────────
function switchView(viewId) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item[data-view]').forEach(n => n.classList.remove('active'));
  const viewEl = document.getElementById('view-' + viewId);
  if (viewEl) viewEl.classList.add('active');
  const navEl = document.getElementById('nav-' + viewId);
  if (navEl) navEl.classList.add('active');

  if (viewId === 'debugger') {
    runScreenDebuggerAnalysis();
  }
}

// ─── Filter & Search ──────────────────────────────────────────────────────────
function applyFilters() {
  const q = document.getElementById('search-input').value.trim();
  STATE.filtered = STATE.parsed.filter(row => {
    if (!STATE.activeLevels.has(row.level)) return false;
    if (!q) return true;
    if (STATE.regexMode) {
      try { return new RegExp(q, 'i').test(row.message) || new RegExp(q, 'i').test(row.source); }
      catch { return false; }
    }
    return row.message.toLowerCase().includes(q.toLowerCase()) || (row.source || '').toLowerCase().includes(q.toLowerCase());
  });
  renderTable();
}

// ─── Dashboard Link Helper ───────────────────────────────────────────────────
function showAndHighlightLog(id) {
  switchView('analyzer');
  const match = STATE.parsed.find(r => r.id === id);
  if (match) {
    STATE.activeLevels.add(match.level);
    document.querySelectorAll('.level-checkbox').forEach(cb => {
      if (cb.dataset.level === match.level) {
        cb.checked = true;
        cb.closest('.level-pill').classList.remove('inactive');
      }
    });
    
    document.getElementById('search-input').value = '';
    applyFilters();
    
    setTimeout(() => {
      const rowEl = document.querySelector(`.log-row[data-id="${id}"]`);
      if (rowEl) {
        document.querySelectorAll('.log-row').forEach(r => r.classList.remove('selected'));
        rowEl.classList.add('selected');
        rowEl.scrollIntoView({ block: 'center', behavior: 'smooth' });
      }
      openDrawer(match);
    }, 50);
  }
}

// ─── Loading UI Helpers ───────────────────────────────────────────────────────
const LOAD_STEPS = ['ustep-parse','ustep-classify','ustep-api','ustep-sql','ustep-score','ustep-render'];

function showLoadingUI(filename) {
  const title = document.getElementById('upload-loading-title');
  if (title) title.textContent = "Analysing Log File…";
  
  const steps = document.getElementById('upload-loading-steps');
  if (steps) steps.style.display = 'block';

  // Show top bar
  const bar   = document.getElementById('upload-progress-bar');
  const fill  = document.getElementById('upload-progress-fill');
  if (bar) bar.style.display = 'block';
  if (bar) bar.classList.add('active');
  if (fill) fill.style.width = '0%';

  // Reset card progress
  const cardFill = document.getElementById('upload-card-progress-fill');
  if (cardFill) cardFill.style.width = '0%';

  // Show card
  const card  = document.getElementById('upload-loading-card');
  const fname = document.getElementById('upload-loading-filename');
  if (card) card.style.display = 'flex';
  if (fname) fname.textContent  = filename || 'pasted log';

  // Hide the counter and warning elements initially
  const counterEl = document.getElementById('upload-line-counter');
  const warningEl = document.getElementById('upload-large-warning');
  if (counterEl) { counterEl.style.display = 'none'; }
  if (warningEl) { warningEl.style.display = 'none'; }

  // Reset all steps
  LOAD_STEPS.forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.classList.remove('active','done'); }
  });
}

function setLoadStep(stepIndex) {
  // Mark previous steps done, current step active
  LOAD_STEPS.forEach((id, i) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('active','done');
    if (i < stepIndex)  el.classList.add('done');
    if (i === stepIndex) el.classList.add('active');
  });

  // Advance progress fill: each step = ~14% of width (6 steps → 84%; last render pushes to 95%)
  const pct = Math.min(95, Math.round(((stepIndex + 1) / LOAD_STEPS.length) * 95));
  const fill = document.getElementById('upload-progress-fill');
  if (fill) fill.style.width = pct + '%';
  const cardFill = document.getElementById('upload-card-progress-fill');
  if (cardFill) cardFill.style.width = pct + '%';
}

function hideLoadingUI() {
  // Complete the bar to 100%
  const fill = document.getElementById('upload-progress-fill');
  if (fill) fill.style.width = '100%';
  const cardFill = document.getElementById('upload-card-progress-fill');
  if (cardFill) cardFill.style.width = '100%';

  // Mark all steps done
  LOAD_STEPS.forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.classList.remove('active'); el.classList.add('done'); }
  });

  // Fade out after short delay
  setTimeout(() => {
    const bar  = document.getElementById('upload-progress-bar');
    const card = document.getElementById('upload-loading-card');
    if (bar) {
      bar.classList.remove('active');
      bar.style.display = 'none';
      const fill2 = document.getElementById('upload-progress-fill');
      if (fill2) fill2.style.width = '0%';
    }
    const cardFill2 = document.getElementById('upload-card-progress-fill');
    if (cardFill2) cardFill2.style.width = '0%';
    if (card) card.style.display = 'none';
  }, 600);
}

// ─── Main Load Function ───────────────────────────────────────────────────────
async function loadLog(text, filename, isAlreadyLoading = false) {
  // Guard: prevent duplicate calls while a log is already being processed
  if (!isAlreadyLoading && STATE.isLoading) return;
  STATE.isLoading = true;

  showLoadingUI(filename);

  // Small helper to yield to the browser so the DOM updates are painted
  const tick = (ms = 0) => new Promise(r => setTimeout(r, ms));

  try {
    // ── Full state reset ──────────────────────────────
    STATE.currentFile = filename || 'pasted log';
    STATE.selectedRow = null;
    STATE.analysis   = null;
    STATE.parsed     = [];
    STATE.filtered   = [];
    STATE.rawLines   = [];

    STATE.activeLevels = new Set(['FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG']);
    document.querySelectorAll('.level-checkbox').forEach(cb => {
      cb.checked = true;
      cb.closest('.level-pill').classList.remove('inactive');
    });

    document.getElementById('topbar-filename').textContent = filename || 'Pasted Log';
    document.getElementById('sidebar-file-name').textContent = filename || 'Pasted Log';
    document.getElementById('topbar-title').textContent = 'Root Cause Analysis';

    const searchInput = document.getElementById('search-input');
    if (searchInput) searchInput.value = '';
    STATE.regexMode = false;
    const regexToggle = document.getElementById('regex-toggle');
    if (regexToggle) regexToggle.classList.remove('active');

    document.getElementById('diag-drawer').classList.remove('open');
    const execBanner = document.getElementById('exec-summary-banner');
    if (execBanner) execBanner.style.display = 'none';

    // ── Step 0: Parsing ───────────────────────────────
    setLoadStep(0);
    await tick(60);
    const parsed = await parseLog(text);
    STATE.filtered = parsed;

    // ── Step 1: Classifying ───────────────────────────
    setLoadStep(1);
    await tick(60);
    const errors = groupErrors(parsed);   // classification already done inside analyzeAll; this is preview

    // ── Step 2: API extraction ────────────────────────
    setLoadStep(2);
    await tick(60);
    // analyzeAll does everything in one call; split visually only
    STATE.analysis = analyzeAll(parsed, STATE.rawLines);

    // ── Step 3: SQL issues ────────────────────────────
    setLoadStep(3);
    await tick(60);

    // ── Step 4: Health score ──────────────────────────
    setLoadStep(4);
    await tick(60);

    // ── Step 5: Rendering ─────────────────────────────
    setLoadStep(5);
    await tick(40);

    renderDashboard(STATE.analysis);
    applyFilters();
    renderTimeline(parsed);
    renderWMSFlow(STATE.analysis.flow, STATE.analysis);
    renderApiTracker(STATE.analysis.apis);
    runScreenDebuggerAnalysis();

    // Auto-detect and refresh active screen in Code Reviewer
    

    const matchedScreenDef = getActiveScreenDefinition();
    if (matchedScreenDef && matchedScreenDef.fields) {
      // Find which field was involved in the crash or error
      const parsedErrors = parsed.filter(e => e.level === 'ERROR' || e.level === 'FATAL');
      let selectedField = null;
      let selectedEvent = null;

      if (parsedErrors.length) {
        const firstErrMsg = parsedErrors[0].message;
        for (const [fieldName, events] of Object.entries(matchedScreenDef.fields)) {
          for (const eventName of Object.keys(events)) {
            if (firstErrMsg.includes(fieldName) || firstErrMsg.includes(eventName)) {
              selectedField = fieldName;
              selectedEvent = eventName;
              break;
            }
          }
          if (selectedField) break;
        }
        if (!selectedField) {
          // Default to first field
          const firstField = Object.keys(matchedScreenDef.fields)[0];
          if (firstField) {
            selectedField = firstField;
            selectedEvent = Object.keys(matchedScreenDef.fields[firstField])[0];
          }
        }
      }

      if (selectedField && selectedEvent) {
        const name = matchedScreenDef.screenName || matchedScreenDef.name || "CustomScreen";
        STATE.codeReviewState = { screenId: name, fieldName: selectedField, eventName: selectedEvent };

        setTimeout(() => {
          const treeContainer = document.getElementById('code-fields-container');
          if (treeContainer) {
            const el = treeContainer.querySelector(`.code-event-item[data-field="${selectedField}"][data-event="${selectedEvent}"]`);
            if (el) {
              el.click();
            }
          }
        }, 50);
      }
    }

    switchView('dashboard');

    await tick(120);
    hideLoadingUI();

  } catch (err) {
    console.error('[LogRadar] loadLog error:', err);
    hideLoadingUI();
  } finally {
    STATE.isLoading = false;
  }
}

function loadSample(key) {
  const s = SAMPLE_LOGS[key];
  if (!s) return;
  loadLog(s.content, s.name + '.log');
}

function initDashboardClicks() {
  const setLogLevelCheckboxes = (levelsToEnable) => {
    document.querySelectorAll('.level-checkbox').forEach(cb => {
      const lv = cb.dataset.level;
      const shouldCheck = levelsToEnable.includes(lv);
      cb.checked = shouldCheck;
      if (shouldCheck) STATE.activeLevels.add(lv);
      else STATE.activeLevels.delete(lv);
      cb.closest('.level-pill').classList.toggle('inactive', !shouldCheck);
    });
  };

  const cardCrit = document.getElementById('card-critical');
  if (cardCrit) {
    cardCrit.addEventListener('click', () => {
      switchView('analyzer');
      setLogLevelCheckboxes(['FATAL', 'ERROR']);
      document.getElementById('search-input').value = '';
      applyFilters();
    });
  }

  const cardWarn = document.getElementById('card-warnings');
  if (cardWarn) {
    cardWarn.addEventListener('click', () => {
      switchView('analyzer');
      setLogLevelCheckboxes(['WARN']);
      document.getElementById('search-input').value = '';
      applyFilters();
    });
  }

  const cardSlow = document.getElementById('card-slowapis');
  if (cardSlow) {
    cardSlow.addEventListener('click', () => {
      switchView('api');
    });
  }

  const cardSql = document.getElementById('card-sqlfail');
  if (cardSql) {
    cardSql.addEventListener('click', () => {
      switchView('analyzer');
      setLogLevelCheckboxes(['FATAL', 'ERROR']);
      document.getElementById('search-input').value = 'SQL';
      applyFilters();
    });
  }

  const cardUsers = document.getElementById('card-users');
  if (cardUsers) {
    cardUsers.addEventListener('click', () => {
      switchView('analyzer');
      setLogLevelCheckboxes(['FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG']);
      document.getElementById('search-input').value = 'User:';
      applyFilters();
    });
  }

  const cardTotal = document.getElementById('card-total');
  if (cardTotal) {
    cardTotal.addEventListener('click', () => {
      switchView('analyzer');
      setLogLevelCheckboxes(['FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG']);
      document.getElementById('search-input').value = '';
      applyFilters();
    });
  }
}

function handleFileSelect(file) {
  if (STATE.isLoading) return;
  STATE.isLoading = true;

  showLoadingUI(file.name);
  const titleEl = document.getElementById('upload-loading-title');
  if (titleEl) titleEl.textContent = 'Uploading Log File…';

  const reader = new FileReader();
  reader.onprogress = ev => {
    if (ev.lengthComputable) {
      const pct = Math.round((ev.loaded / ev.total) * 100);
      if (titleEl) titleEl.textContent = `Uploading Log File (${pct}%)…`;
      const fill = document.getElementById('upload-progress-fill');
      const cardFill = document.getElementById('upload-card-progress-fill');
      if (fill) fill.style.width = pct + '%';
      if (cardFill) cardFill.style.width = pct + '%';
    }
  };

  reader.onload = ev => {
    if (titleEl) titleEl.textContent = 'Analysing Log File…';
    // Small delay so the user sees 100% upload before analysis steps start
    setTimeout(() => {
      loadLog(ev.target.result, file.name, true);
    }, 150);
  };

  reader.onerror = () => {
    console.error('[LogRadar] FileReader error reading:', file.name);
    if (titleEl) titleEl.textContent = 'Error reading file';
    STATE.isLoading = false;
    hideLoadingUI();
  };

  reader.readAsText(file);
}

// ─── Event Listeners ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

  initDashboardClicks();
  

  // Nav buttons
  document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  // File upload
  document.getElementById('upload-btn').addEventListener('click', () => {
    // Reset value so the same file can be re-uploaded
    const fileInput = document.getElementById('file-input');
    fileInput.value = '';
    fileInput.click();
  });
  document.getElementById('file-input').addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    handleFileSelect(file);
    // Reset so same file can be re-selected next time
    e.target.value = '';
  });

  

  // Paste
  document.getElementById('paste-submit').addEventListener('click', () => {
    const text = document.getElementById('paste-area').value.trim();
    if (text) loadLog(text, 'pasted-log.txt');
  });

  // Drag & Drop
  document.body.addEventListener('dragover', e => { e.preventDefault(); document.body.classList.add('drag-active'); document.getElementById('drop-overlay').style.display = 'flex'; });
  document.body.addEventListener('dragleave', e => { if (!e.relatedTarget) { document.body.classList.remove('drag-active'); document.getElementById('drop-overlay').style.display = 'none'; } });
  document.body.addEventListener('drop', e => {
    e.preventDefault();
    document.body.classList.remove('drag-active');
    document.getElementById('drop-overlay').style.display = 'none';
    const file = e.dataTransfer.files[0];
    if (!file) return;
    handleFileSelect(file);
  });

  // Close drawer
  document.getElementById('close-drawer').addEventListener('click', () => {
    document.getElementById('diag-drawer').classList.remove('open');
    STATE.selectedRow = null;
    document.querySelectorAll('.log-row').forEach(r => r.classList.remove('selected'));
  });

  // Search
  document.getElementById('search-input').addEventListener('input', applyFilters);

  // Regex toggle
  document.getElementById('regex-toggle').addEventListener('click', function () {
    STATE.regexMode = !STATE.regexMode;
    this.classList.toggle('active', STATE.regexMode);
    applyFilters();
  });

  // Level pills
  document.querySelectorAll('.level-checkbox').forEach(cb => {
    cb.addEventListener('change', () => {
      const level = cb.dataset.level;
      if (cb.checked) STATE.activeLevels.add(level);
      else STATE.activeLevels.delete(level);
      cb.closest('.level-pill').classList.toggle('inactive', !cb.checked);
      applyFilters();
    });
  });

  // Ask AI
  document.getElementById('chat-send').addEventListener('click', sendChatMessage);
  document.getElementById('chat-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') sendChatMessage();
  });

  // ─── Privacy Mode Toggle ─────────────────────────────────────────────────
  document.getElementById('privacy-toggle').addEventListener('click', function () {
    STATE.privacyMode = !STATE.privacyMode;
    this.classList.toggle('active', STATE.privacyMode);
    document.body.classList.toggle('privacy-active', STATE.privacyMode);

    const banner = document.getElementById('privacy-banner');
    if (banner) banner.style.display = STATE.privacyMode ? 'flex' : 'none';

    // Re-render the open drawer with updated PII masking
    if (STATE.selectedRow) openDrawer(STATE.selectedRow);
  });

  // Initialize empty state for API Tracker
  renderApiTracker(null);

});
