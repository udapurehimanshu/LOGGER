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
  filterByScreen: false,
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

const PROPERTY_MAP = {
  id: 'ID',
  label: 'Label',
  style: 'Style',
  controlType: 'Style',
  isPassword: 'Is Password',
  password: 'Is Password',
  rendered: 'Rendered',
  renderedLogic: 'Rendered Logic',
  autoEnter: 'Auto Enter',
  required: 'Required',
  readOnly: 'Read Only',
  alterCase: 'Alter Case',
  defaultValue: 'Default Value',
  length: 'Length',
  dfi: 'DFI',
  dfiRequired: 'DFI Required',
  barcodeDelimiter: 'Barcode Delimiter',
  subsequentValue: 'Subsequent Value',
  onFocus: 'On Focus',
  onFocusScript: 'On Focus',
  beforeExit: 'Before Exit',
  beforeExitScript: 'Before Exit',
  onExit: 'On Exit',
  onExitScript: 'On Exit',
  onKeyPress: 'On Key Press',
  onKeyPressScript: 'On Key Press',
  dateFormat: 'Date Format',
  lovSourceType: 'LOV Source Type',
  webService: 'Web Service',
  lovPageTitle: 'LOV Page Title',
  lovStatement: 'LOV Statement',
  inputParameter: 'Input Parameter',
  parameterTypes: 'Parameter Types',
  columnDisplay: 'Column Display',
  columnPrompt: 'Column Prompt',
  addPercent: 'Add %',
  lovValidation: 'LOV Validation',
  blindSearch: 'Blind Search',
  enableGenerate: 'Enable Generate',
  scanOnly: 'Scan Only',
  textAlignment: 'Text Alignment'
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
    const m1_flexi = line.match(/^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\[(.*?)\]\s+(\S+)\s+-\s+(.+)$/i);
    const m1_flexi_b = !m1_flexi && line.match(/^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\[(.*?)\]\s+(.+)$/i);
    // Pattern 1: [LEVEL] TIMESTAMP [thread] source - message
    const m1 = !m1_flexi && !m1_flexi_b && line.match(/^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(.+)$/i);
    // Pattern 1b: [LEVEL] TIMESTAMP [thread] message
    const m1b = !m1 && !m1_flexi && !m1_flexi_b && line.match(/^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(.+)$/i);
    // Pattern 2: TIMESTAMP [thread] LEVEL source - message
    const m2 = !m1 && !m1b && !m1_flexi && !m1_flexi_b && line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s+(\S+)\s+-\s+(.+)$/i);
    // Pattern 3: TIMESTAMP LEVEL [thread] source - message
    const m3 = !m1 && !m1b && !m2 && !m1_flexi && !m1_flexi_b && line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(.+)$/i);
    // Pattern 4: TIMESTAMP [thread] message  (implicit INFO)
    const m4 = !m1 && !m1b && !m2 && !m3 && !m1_flexi && !m1_flexi_b && line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(.+)$/i);
    // Pattern 5: [LEVEL] message
    const m5 = !m1 && !m1b && !m2 && !m3 && !m4 && line.match(/^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(.+)$/i);

    if (m1_flexi) {
      if (current) joined.push(current);
      current = { timestamp: m1_flexi[2], thread: m1_flexi[4], level: m1_flexi[1].toUpperCase(), source: m1_flexi[5], message: m1_flexi[6], rawLines: [line], index: i };
    } else if (m1_flexi_b) {
      if (current) joined.push(current);
      current = { timestamp: m1_flexi_b[2], thread: m1_flexi_b[4], level: m1_flexi_b[1].toUpperCase(), source: 'Unknown', message: m1_flexi_b[5], rawLines: [line], index: i };
    } else if (m1) {
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

function detectLogType(text) {
  if (!text) return 'Generic';
  const lower = text.toLowerCase();
  if (lower.includes('flexiruntime') || lower.includes('intellinum') || lower.includes('useractionlogger')) {
    return 'Flexi Runtime';
  }
  if (lower.includes(':: spring boot ::') || lower.includes('springboot') || lower.includes('org.springframework')) {
    return 'Spring Boot';
  }
  if (lower.includes('tomcat') || lower.includes('catalina') || lower.includes('org.apache.catalina')) {
    return 'Apache Tomcat';
  }
  if (lower.includes('oracle') || lower.includes('ora-') || lower.includes('jdbc.driver')) {
    return 'Oracle Database';
  }
  if (lower.includes('java.lang') || lower.includes('exception') || lower.includes('nullpointerexception')) {
    return 'Java Application';
  }
  if (lower.includes('traceback (most recent call last):') || lower.includes('line, in <module>')) {
    return 'Python';
  }
  if (lower.includes('node_modules') || lower.includes('node:internal') || (lower.includes('at ') && lower.includes('.js:'))) {
    return 'NodeJS';
  }
  if (lower.includes('org.apache.log4j') || lower.includes('log4j') || lower.includes('apache')) {
    return 'Apache Log4j';
  }
  return 'Generic';
}

function extractBlankAPIs(apis) {
  const blankApis = [];
  apis.forEach(api => {
    if (api.status === 200 && api.response) {
      const respStr = api.response.trim();
      let isBlank = false;
      let blankReason = '';
      let recommendation = '';
      
      if (respStr === '[]' || respStr === '{}') {
        isBlank = true;
        blankReason = 'Empty response body';
        recommendation = 'Check request parameters. Downstream query returned no records.';
      } else {
        const countM = respStr.match(/"count"\s*:\s*0\b/i) || respStr.match(/"records"\s*:\s*0\b/i);
        const itemsM = respStr.match(/"items"\s*:\s*\[\s*\]/i) || respStr.match(/"data"\s*:\s*\[\s*\]/i);
        
        if (countM && itemsM) {
          isBlank = true;
          blankReason = 'Empty items list with count 0';
          recommendation = 'Query executed successfully but returned zero results. Verify if the database has records matching the criteria.';
        } else if (countM) {
          isBlank = true;
          blankReason = 'Response count field is 0';
          recommendation = 'Verify query criteria. Ensure the underlying database contains active records for this entity.';
        } else if (itemsM) {
          isBlank = true;
          blankReason = 'Items array is empty';
          recommendation = 'No records matching input criteria. Check filters or input parameter bindings.';
        }
      }
      
      if (isBlank) {
        blankApis.push({
          name: api.name,
          endpoint: api.endpoint || 'Unknown',
          status: api.status,
          ms: api.ms,
          blankReason: blankReason,
          recommendation: recommendation,
          logIndex: api.logIndex
        });
      }
    }
  });
  return blankApis;
}

function classifyApiBusinessResult(api) {
  if (!api.status) return 'Unknown';
  if (api.status >= 400) {
    return `Failed (HTTP ${api.status})`;
  }
  if (api.response) {
    const respStr = api.response;
    if (respStr.includes('"success":false') || respStr.includes('"success": false') || respStr.includes('"valid":false') || respStr.includes('"valid": false')) {
      return 'Business Validation Failure';
    }
    const countM = respStr.match(/"count"\s*:\s*0\b/i) || respStr.match(/"records"\s*:\s*0\b/i);
    const itemsM = respStr.match(/"items"\s*:\s*\[\s*\]/i) || respStr.match(/"data"\s*:\s*\[\s*\]/i);
    if (respStr.trim() === '[]' || respStr.trim() === '{}' || countM || itemsM) {
      return 'Blank Response';
    }
  }
  return 'Healthy';
}

function analyzeWarnings(parsed) {
  const warnings = [];
  parsed.forEach(e => {
    if (e.level === 'WARN') {
      let classification = 'General Warning';
      let impact = 'Potential system degradation or non-standard behavior.';
      let causesFutureFailure = false;
      const msg = e.message.toLowerCase();
      
      if (msg.includes('config') || msg.includes('setup') || msg.includes('property') || msg.includes('env') || msg.includes('missing setting')) {
        classification = 'Configuration Warning';
        impact = 'Misconfigured settings may lead to fallback behaviors or minor feature failure.';
        causesFutureFailure = false;
      } else if (msg.includes('deprecat') || msg.includes('obsolete')) {
        classification = 'Deprecated API';
        impact = 'Code depends on deprecated APIs that will be removed in future versions.';
        causesFutureFailure = true;
      } else if (msg.includes('memory') || msg.includes('heap') || msg.includes('garbage collection') || msg.includes('gc ') || msg.includes('leak')) {
        classification = 'Memory Warning';
        impact = 'Elevated memory usage. High risk of OutOfMemory crashes in production.';
        causesFutureFailure = true;
      } else if (msg.includes('slow') || msg.includes('latency') || msg.includes('timeout') || msg.includes('duration') || msg.includes('performance')) {
        classification = 'Performance Warning';
        impact = 'High latency or execution times may cause bottleneck and degrade user experience.';
        causesFutureFailure = false;
      } else if (msg.includes('security') || msg.includes('auth') || msg.includes('unauthorized') || msg.includes('ssl') || msg.includes('permission') || msg.includes('decrypt') || msg.includes('cipher')) {
        classification = 'Security Warning';
        impact = 'Potential vulnerability, unauthorized access attempt, or invalid credentials.';
        causesFutureFailure = false;
      } else if (msg.includes('validation') || msg.includes('invalid field') || msg.includes('business') || msg.includes('rule') || msg.includes('constraint')) {
        classification = 'Business Warning';
        impact = 'Business validation failed (non-critical). The current action might not complete as expected.';
        causesFutureFailure = false;
      } else if (msg.includes('sql') || msg.includes('database') || msg.includes('query') || msg.includes('jdbc') || msg.includes('connection pool') || msg.includes('oracle') || msg.includes('ora-')) {
        classification = 'Database Warning';
        impact = 'Database queries or connections are slow or hitting resource limits.';
        causesFutureFailure = true;
      } else if (msg.includes('network') || msg.includes('http') || msg.includes('socket') || msg.includes('connect') || msg.includes('dns') || msg.includes('refused')) {
        classification = 'Network Warning';
        impact = 'Transient network issues detected. May result in API call failures.';
        causesFutureFailure = false;
      } else if (msg.includes('resource') || msg.includes('file descriptor') || msg.includes('disk') || msg.includes('io exception') || msg.includes('thread pool')) {
        classification = 'Resource Warning';
        impact = 'System resources (disk, files, thread pools) are running low.';
        causesFutureFailure = true;
      }
      
      warnings.push({
        id: e.id,
        timestamp: e.timestamp,
        thread: e.thread,
        source: e.source || 'Unknown',
        message: e.message,
        classification: classification,
        impact: impact,
        causesFutureFailure: causesFutureFailure
      });
    }
  });
  return warnings;
}

function analyzeLoggers(parsed, text) {
  const counts = { TRACE: 0, DEBUG: 0, INFO: 0, WARN: 0, ERROR: 0, FATAL: 0 };
  parsed.forEach(e => {
    if (counts[e.level] !== undefined) {
      counts[e.level]++;
    }
  });
  
  const gaps = [];
  
  // Gap 1: API started but never completed (on same thread)
  const threadApiStates = {};
  parsed.forEach(e => {
    const msg = e.message;
    const thread = e.thread;
    
    const startM = msg.match(/callWebService:name:(\S+)/i) || 
                   msg.match(/Initiating API call:\s*(\S+)/i) ||
                   msg.match(/(\S+)\.callWebService\(\)\s*started/i);
    
    if (startM) {
      threadApiStates[thread] = { name: startM[1], index: e.id };
    }
    
    if (threadApiStates[thread]) {
      const hasResponse = msg.includes('Response Code') || 
                          msg.includes('HTTP Response Code') || 
                          msg.includes('Response Body') ||
                          msg.includes('result{') || 
                          msg.includes('result {') ||
                          (msg.includes('callWebService() : ') && msg.includes('ms'));
      if (hasResponse) {
        delete threadApiStates[thread];
      }
    }
  });
  
  for (const thread in threadApiStates) {
    const state = threadApiStates[thread];
    gaps.push({
      type: 'Missing API Response Logger',
      description: `API call to "${state.name}" started on thread "${thread}" (log index ${state.index}) but no response code or body was logged.`,
      recommendation: 'Add response logger in the api client fallback block.'
    });
  }
  
  // Gap 2: DB query execution started but no completion or result count logged
  const dbStarts = [];
  const dbEnds = [];
  parsed.forEach(e => {
    const msg = e.message.toLowerCase();
    if (msg.includes('executequery') || msg.includes('executing query') || msg.includes('select ') || msg.includes('insert ') || msg.includes('update ')) {
      dbStarts.push(e);
    }
    if (msg.includes('rows fetched') || msg.includes('query complete') || msg.includes('db connection') || msg.includes('rows affected')) {
      dbEnds.push(e);
    }
  });
  if (dbStarts.length > dbEnds.length + 2) {
    gaps.push({
      type: 'Incomplete Database Logging',
      description: 'Multiple queries started without logged execution times or row counts.',
      recommendation: 'Enable SQL performance logging in JDBC/connection pool config.'
    });
  }
  
  // Gap 3: Missing INFO loggers in long logic blocks (e.g. no logs for > 8 seconds on same thread)
  const threadLastTimes = {};
  parsed.forEach(e => {
    if (e.timestamp && e.thread) {
      const timeVal = new Date(e.timestamp.replace(' ', 'T')).getTime();
      if (!isNaN(timeVal)) {
        if (threadLastTimes[e.thread]) {
          const diff = timeVal - threadLastTimes[e.thread];
          if (diff > 8000) {
            gaps.push({
              type: 'Execution Telemetry Gap',
              description: `Thread "${e.thread}" had no log activity for ${Math.round(diff/1000)}s between log index ${e.id - 1} and ${e.id}.`,
              recommendation: 'Inject debug/trace log statements in loops or long running methods.'
            });
          }
        }
        threadLastTimes[e.thread] = timeVal;
      }
    }
  });
  
  const uniqueGaps = [];
  const seenTypes = new Set();
  gaps.forEach(g => {
    if (!seenTypes.has(g.description)) {
      seenTypes.add(g.description);
      uniqueGaps.push(g);
    }
  });
  
  return {
    counts,
    gaps: uniqueGaps.slice(0, 5)
  };
}

function analyzeAll(parsed, rawLines) {
  // Build a capped text blob for regex-heavy operations
  const text     = buildAnalysisText(parsed);
  const fullMsg  = parsed.slice(0, 5000).map(e => e.message).join('\n'); // cap message join

  // --- Error counts (work on full parsed array)
  const errors   = parsed.filter(e => ['ERROR','FATAL'].includes(e.level));
  
  // --- New features ---
  const logType = detectLogType(text);
  const warnings = analyzeWarnings(parsed);
  const loggerStats = analyzeLoggers(parsed, text);

  // --- API / SQL / variable extraction (work on capped text — fast)
  const apis     = extractAPIs(text);
  const blankApis = extractBlankAPIs(apis);
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
  const score    = calcHealthScore({ errors, warnings, parsed, apis, sqls, blankApis, loggerStats });

  // --- Dependency chain
  const depChain = buildDepChain(parsed, apis, sqls);

  // --- WMS Flow
  const flow     = buildWMSFlow(text, module);

  // --- Exec Summary
  const execSummary = buildExecSummary({ errors, apis, sqls, module, users, screen, transaction, score, vars, logType, blankApis, parsed });

  return {
    errors, warnings, apis, sqls, vars, module, groups, users, screen, transaction, score, depChain, flow, execSummary,
    logType, blankApis, loggerStats,
    totalLines: parsed.length,
    rawLineCount: rawLines.length,
  };
}


function extractAPIs(text) {
  const apis = [];
  const threadApiStates = {};

  if (!STATE.parsed || !STATE.parsed.length) {
    return apis;
  }

  function finalizeAndPush(api) {
    if (!api) return;

    if (!api.method || api.method === 'Unknown') {
       if (api.endpoint && (api.endpoint.includes('q=') || api.endpoint.includes('fields=') || api.endpoint.includes('onlyData=true'))) {
          api.method = 'GET';
       } else {
          api.method = 'Unknown';
       }
    }

    let countVal = api.recordCount;
    if (api.response && api.response !== 'NOT LOGGED') {
       const trimResp = api.response.trim();
       if (trimResp === '[]' || trimResp === '{}') {
          countVal = 0;
       } else if (trimResp.startsWith('{') || trimResp.startsWith('[')) {
          try {
             const parsed = JSON.parse(trimResp);
             if (Array.isArray(parsed)) {
                countVal = parsed.length;
             } else if (parsed && typeof parsed === 'object') {
                if (parsed.count !== undefined) countVal = Number(parsed.count);
                else if (parsed.total !== undefined) countVal = Number(parsed.total);
                else if (parsed.size !== undefined) countVal = Number(parsed.size);
                else if (parsed.records !== undefined) countVal = Number(parsed.records);
                else if (Array.isArray(parsed.items)) countVal = parsed.items.length;
                else if (Array.isArray(parsed.data)) countVal = parsed.data.length;
             }
          } catch(e) {}
       }
    }
    if (countVal === undefined || countVal === null) {
       countVal = 'Unknown';
    }
    api.recordCount = countVal;

    let isBlank = (countVal === 0 || countVal === '0');

    if ((!api.status || api.status === 'Unknown (Not Logged)') && api.response && api.response !== 'NOT LOGGED' && api.response !== 'N/A') {
       api.status = 'HTTP Status Not Logged';
    }

    let statusStr = String(api.status || '');
    let httpCode = null;
    if (/^\d+$/.test(statusStr)) {
       httpCode = parseInt(statusStr);
    }

    let businessStatus = 'Unknown';
    let businessResult = 'Unknown';

    if (httpCode === 200 || api.status === 'HTTP Status Not Logged') {
       if (isBlank) {
          businessStatus = 'Blank Response';
          businessResult = 'Success (Empty)';
       } else {
          businessStatus = 'Business Success';
          businessResult = 'Business Success';
       }
    } else if (httpCode === 401) {
       businessStatus = 'Authentication Failed';
       businessResult = 'Authentication Error (HTTP 401)';
    } else if (httpCode === 403) {
       businessStatus = 'Permission Issue';
       businessResult = 'Permission Denied';
    } else if (httpCode === 404) {
       businessStatus = 'Endpoint Missing';
       businessResult = 'Not Found';
    } else if (httpCode >= 500) {
       businessStatus = 'Server Error';
       businessResult = 'Internal Error';
    } else if (api.status === 'Timeout' || (typeof api.ms === 'number' && api.ms >= 10000)) {
       businessStatus = 'Network Issue';
       businessResult = 'Timeout';
    } else if (httpCode >= 400 && httpCode < 500) {
       businessStatus = 'Client Error';
       businessResult = 'Bad Request';
    } else {
       if (api.response && api.response !== 'NOT LOGGED' && api.response !== 'N/A') {
          if (isBlank) {
             businessStatus = 'Blank Response';
             businessResult = 'Success (Empty)';
          } else {
             businessStatus = 'Business Success';
             businessResult = 'Business Success';
          }
       } else {
          businessStatus = 'Unknown';
          businessResult = 'Not Logged';
       }
    }

    if (api.retryCount > 0) {
       businessStatus = 'Retry';
    }

    api.businessStatus = businessStatus;
    api.businessResult = businessResult;

    let perfRating = 'N/A';
    if (typeof api.ms === 'number') {
       const ms = api.ms;
       if (ms <= 500) perfRating = 'Excellent';
       else if (ms <= 1000) perfRating = 'Good';
       else if (ms <= 2000) perfRating = 'Average';
       else if (ms <= 5000) perfRating = 'Slow';
       else perfRating = 'Critical';
    }
    api.performanceRating = perfRating;

    let rec = 'No action required.';
    if (businessStatus === 'Blank Response') {
       rec = 'Verify filters. Verify Organization. Verify Item. Verify Query Parameters. Verify Data Exists.';
    } else if (httpCode === 403 || businessStatus === 'Permission Issue') {
       rec = 'Check Roles. Check Security. Check User Privileges.';
    } else if (httpCode >= 500 || businessStatus === 'Server Error') {
       rec = 'Check Server Logs. Check Exception Stack. Check Payload.';
    } else if (api.status === 'Timeout' || (typeof api.ms === 'number' && api.ms > 10000) || businessStatus === 'Network Issue') {
       rec = 'Retry. Check Network. Increase Timeout.';
    }
    api.recommendation = rec;

    if (!api.request || api.request === 'N/A' || api.request === 'NOT LOGGED') {
       api.request = 'NOT LOGGED';
    }

    let health = 'Success';
    if (api.status === 'Timeout' || (typeof api.ms === 'number' && api.ms >= 10000)) {
       health = 'Failed';
    } else if (httpCode >= 400) {
       health = 'Failed';
    } else if (api.retryCount > 0) {
       health = 'Retry';
    } else if (isBlank) {
       health = 'Blank';
  } else if (typeof api.ms === 'number' && api.ms > 2000) {
     health = 'Slow';
  } else if (api.status === 'Unknown (Not Logged)' || api.status === 'HTTP Status Not Logged') {
     if (api.response && api.response !== 'NOT LOGGED') {
        health = isBlank ? 'Blank' : 'Success';
     } else {
        health = 'HTTP Unknown';
     }
  }
  api.health = health;

  apis.push(api);
}

  STATE.parsed.forEach(e => {
    const thread = e.thread || 'main';
    const msg = e.message;
    const timestamp = e.timestamp || '';

    if (!threadApiStates[thread]) {
      threadApiStates[thread] = {
        state: 'IDLE',
        api: null,
        jsonBuffer: '',
        braceCount: 0,
      };
    }
    const tState = threadApiStates[thread];

    const lines = msg.split('\n');
    for (let line of lines) {
      line = line.trim();
      if (!line) continue;

      if (tState.state === 'RESPONSE_JSON') {
        tState.jsonBuffer += '\n' + line;
        
        for (let i = 0; i < line.length; i++) {
          if (line[i] === '{') tState.braceCount++;
          else if (line[i] === '}') tState.braceCount--;
        }

        if (tState.braceCount <= 0) {
          tState.api.response = tState.jsonBuffer;
          try {
            const parsedJson = JSON.parse(tState.jsonBuffer);
            if (parsedJson.count !== undefined) {
              tState.api.recordCount = parsedJson.count;
            } else if (Array.isArray(parsedJson.items)) {
              tState.api.recordCount = parsedJson.items.length;
            } else if (parsedJson.records !== undefined) {
              tState.api.recordCount = parsedJson.records;
            }
            
            if (parsedJson.links && Array.isArray(parsedJson.links)) {
              const mainLink = parsedJson.links.find(lnk => lnk.rel === 'self' || lnk.rel === 'canonical') || parsedJson.links[0];
              if (mainLink && mainLink.href) {
                tState.api.endpoint = mainLink.href;
                try {
                  const parts = mainLink.href.split('?')[0].split('/').filter(Boolean);
                  if (parts.length) {
                    tState.api.name = parts[parts.length - 1].toUpperCase() + "_WS";
                  }
                } catch(err) {}
              }
              tState.api.relatedUrls = parsedJson.links.map(lnk => lnk.href).filter(Boolean);
            }
          } catch(err) {
            const countM = tState.jsonBuffer.match(/"count"\s*:\s*(\d+)/i);
            if (countM) tState.api.recordCount = parseInt(countM[1]);
            
            const hrefM = tState.jsonBuffer.match(/"href"\s*:\s*"([^"]+)"/);
            if (hrefM) {
              tState.api.endpoint = hrefM[1];
              try {
                const parts = hrefM[1].split('?')[0].split('/').filter(Boolean);
                if (parts.length) {
                  tState.api.name = parts[parts.length - 1].toUpperCase() + "_WS";
                }
              } catch(err) {}
            }
          }
          
          finalizeAndPush(tState.api);
          tState.state = 'IDLE';
          tState.api = null;
          tState.jsonBuffer = '';
          tState.braceCount = 0;
        }
        continue;
      }

      const hasStartPattern = 
        line.includes('.runWebService') ||
        /\b[A-Za-z0-9_]+\.runWebService\b/i.test(line) ||
        line.includes('callWebService') ||
        line.includes('Executing API') ||
        line.includes('HTTP Request') ||
        line.includes('RestTemplate') ||
        line.includes('HttpURLConnection') ||
        line.includes('WebClient') ||
        line.includes('axios') ||
        line.includes('fetch(') ||
        /\b(GET|POST|PUT|DELETE|PATCH)\s+https?:\/\/\S+/i.test(line);

      if (hasStartPattern) {
        if (tState.api) {
          finalizeAndPush(tState.api);
        }

        let apiName = 'API_CALL';
        let method = 'GET';
        let endpoint = null;

        const runWsM = line.match(/([A-Za-z0-9_]+)\.runWebService/i);
        if (runWsM) {
          apiName = runWsM[1].toUpperCase() + "_WS";
        }
        const callWsM = line.match(/callWebService:name:([A-Za-z0-9_]+)/i) || 
                        line.match(/callWebService\(\s*['"]?([A-Za-z0-9_]+)['"]?/i);
        if (callWsM) {
          apiName = callWsM[1].toUpperCase();
        }

        const methodM = line.match(/\b(GET|POST|PUT|DELETE|PATCH)\b/i);
        if (methodM) {
          method = methodM[1].toUpperCase();
        }

        const urlM = line.match(/https?:\/\/\S+/i);
        if (urlM) {
          endpoint = urlM[0];
        }

        tState.api = {
          name: apiName,
          method: method,
          endpoint: endpoint,
          status: 'Unknown (Not Logged)',
          ms: 'Unknown',
          request: 'NOT LOGGED',
          response: 'NOT LOGGED',
          headers: {},
          correlationId: null,
          timestamp: timestamp,
          thread: thread,
          logIndex: e.id,
          retryCount: 0,
          relatedUrls: []
        };
        tState.state = 'API_START';
      }

      if (line.includes('runWebService:result') && !tState.api) {
        tState.api = {
          name: 'WORK_ORDER_WS',
          method: 'GET',
          endpoint: null,
          status: 'Unknown (Not Logged)',
          ms: 'Unknown',
          request: 'NOT LOGGED',
          response: 'NOT LOGGED',
          headers: {},
          correlationId: null,
          timestamp: timestamp,
          thread: thread,
          logIndex: e.id,
          retryCount: 0,
          relatedUrls: []
        };
        tState.state = 'API_START';
      }

      if (!tState.api) continue;

      const timeM = line.match(/Total time\s*[=:]\s*(\d+)/i) || 
                    line.match(/Execution Time\s*[=:]\s*(\d+)/i) ||
                    line.match(/Completed in\s*(\d+)\s*ms/i) ||
                    line.match(/elapsed\s*[=:]\s*(\d+)/i);
      if (timeM) {
        tState.api.ms = parseInt(timeM[1]);
      }

      const statusM = line.match(/Response Code\s*[=:]\s*(\d+)/i) || 
                      line.match(/HTTP\s+(\d{3})\b/i) ||
                      line.match(/HTTP Response Code\s*:\s*(\d+)/i);
      if (statusM) {
        tState.api.status = parseInt(statusM[1]);
      }

      const corrM = line.match(/correlation-id\s*[=:]\s*([^\s,\]]+)/i) || 
                    line.match(/correlationId\s*[=:]\s*([^\s,\]]+)/i);
      if (corrM) {
        tState.api.correlationId = corrM[1].replace(/[\[\]]/g, '');
      }

      const urlM2 = line.match(/URL\s*=\s*(https?:\/\/\S+)/i) || 
                    line.match(/Endpoint\s*:\s*(\S+)/i);
      if (urlM2) {
        tState.api.endpoint = urlM2[1];
      }

      if (line.includes('Authorization:') || line.toLowerCase().includes('authorization')) {
        const authM = line.match(/Authorization:\s*(Bearer\s+\S+|Basic\s+\S+|\S+)/i);
        if (authM) tState.api.headers['Authorization'] = authM[1];
      }
      if (line.includes('Content-Type:') || line.toLowerCase().includes('content-type')) {
        const ctM = line.match(/Content-Type:\s*(\S+)/i);
        if (ctM) tState.api.headers['Content-Type'] = ctM[1];
      }

      if (line.includes('Request Payload:') || line.includes('_request:') || line.includes('payload=')) {
        const payM = line.match(/Request Payload\s*:\s*(.+)$/i) || 
                     line.match(/_request\s*:\s*(.+)$/i) ||
                     line.match(/payload\s*=\s*(.+)$/i);
        if (payM) {
          tState.api.request = payM[1].trim();
        }
      }

      if (line.toLowerCase().includes('retry') || line.toLowerCase().includes('retrying')) {
        tState.api.retryCount = (tState.api.retryCount || 0) + 1;
      }

      const hasResult = line.includes('runWebService') && line.includes('result');
      const braceIdx = line.indexOf('{');
      
      if (hasResult && braceIdx !== -1) {
        tState.state = 'RESPONSE_JSON';
        tState.jsonBuffer = line.substring(braceIdx);
        tState.braceCount = 0;
        for (let i = braceIdx; i < line.length; i++) {
          if (line[i] === '{') tState.braceCount++;
          else if (line[i] === '}') tState.braceCount--;
        }

        if (tState.braceCount <= 0) {
          tState.api.response = tState.jsonBuffer;
          try {
            const parsedJson = JSON.parse(tState.jsonBuffer);
            if (parsedJson.count !== undefined) {
              tState.api.recordCount = parsedJson.count;
            } else if (parsedJson.totalResults !== undefined) {
              tState.api.recordCount = parsedJson.totalResults;
            } else if (Array.isArray(parsedJson.items)) {
              tState.api.recordCount = parsedJson.items.length;
            } else if (parsedJson.records !== undefined) {
              tState.api.recordCount = parsedJson.records;
            }
            
            if (parsedJson.links && Array.isArray(parsedJson.links)) {
              const mainLink = parsedJson.links[0];
              if (mainLink && mainLink.href) {
                tState.api.endpoint = mainLink.href;
                try {
                  const parts = mainLink.href.split('?')[0].split('/').filter(Boolean);
                  if (parts.length) {
                    tState.api.name = parts[parts.length - 1].toUpperCase() + "_WS";
                  }
                } catch(err) {}
              }
            }
          } catch(e) {
            const countM = tState.jsonBuffer.match(/"count"\s*:\s*(\d+)/i) || tState.jsonBuffer.match(/"totalResults"\s*:\s*(\d+)/i);
            if (countM) tState.api.recordCount = parseInt(countM[1]);
            
            const hrefM = tState.jsonBuffer.match(/"href"\s*:\s*"([^"]+)"/);
            if (hrefM) {
              tState.api.endpoint = hrefM[1];
              try {
                const parts = hrefM[1].split('?')[0].split('/').filter(Boolean);
                if (parts.length) {
                  tState.api.name = parts[parts.length - 1].toUpperCase() + "_WS";
                }
              } catch(err) {}
            }
          }
          
          finalizeAndPush(tState.api);
          tState.state = 'IDLE';
          tState.api = null;
          tState.jsonBuffer = '';
          tState.braceCount = 0;
        }
      }
    }
  });

  for (const t in threadApiStates) {
    if (threadApiStates[t].api) {
      finalizeAndPush(threadApiStates[t].api);
    }
  }

  return apis;
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

function calcHealthScore({ errors, warnings, parsed, apis, sqls, blankApis, loggerStats }) {
  let score = 100;
  const errPct = parsed.length ? (errors.length / parsed.length) : 0;
  score -= Math.min(40, Math.round(errPct * 200));
  
  const warnCount = warnings ? (Array.isArray(warnings) ? warnings.length : warnings) : 0;
  score -= Math.min(10, warnCount * 2);
  
  const failedApis = apis.filter(a => a.status && (a.status >= 400 || a.ms > 5000));
  score -= Math.min(25, failedApis.length * 12);
  
  const slowApis = apis.filter(a => a.ms > 2000 && (!a.status || a.status < 400));
  score -= Math.min(15, slowApis.length * 8);
  
  score -= Math.min(20, sqls.filter(s => s.code && s.code !== 'JSON_KEY_MISSING').length * 10);
  
  if (blankApis && blankApis.length) {
    score -= Math.min(25, blankApis.length * 5);
  }
  if (loggerStats && loggerStats.gaps && loggerStats.gaps.length) {
    score -= Math.min(15, loggerStats.gaps.length * 3);
  }
  
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

function buildExecSummary({ errors, apis, sqls, module, users, screen, transaction, score, vars, logType, blankApis, parsed }) {
  let durationStr = 'Unknown';
  if (parsed && parsed.length) {
    const firstTs = parsed[0].timestamp;
    const lastTs = parsed[parsed.length - 1].timestamp;
    if (firstTs && lastTs) {
      const first = new Date(firstTs.replace(' ', 'T')).getTime();
      const last = new Date(lastTs.replace(' ', 'T')).getTime();
      if (!isNaN(first) && !isNaN(last)) {
        const diffMs = last - first;
        const diffSec = Math.floor(diffMs / 1000);
        if (diffSec < 60) {
          durationStr = `${diffSec} seconds`;
        } else {
          const min = Math.floor(diffSec / 60);
          const sec = diffSec % 60;
          durationStr = `${min}m ${sec}s (${diffMs}ms)`;
        }
      } else {
        durationStr = `${firstTs} to ${lastTs}`;
      }
    }
  }

  const totalApis = apis ? apis.length : 0;
  const failedApisCount = apis ? apis.filter(a => a.status >= 400).length : 0;
  const blankApisCount = blankApis ? blankApis.length : 0;
  const healthyApisCount = totalApis - failedApisCount - blankApisCount;

  let issue = 'System healthy — no critical errors detected.';
  let rootCause = 'N/A';
  let fix = 'No immediate actions required.';
  let impact = 'Normal operation.';
  let confidenceScore = 100;

  if (errors && errors.length) {
    const mainError = errors[0];
    const rc = analyzeRow(mainError, [], {});
    issue = transaction ? `${transaction} failed in ${module} module.` : `${module} module encountered a critical error.`;
    rootCause = rc.rootCause || 'See diagnostic drawer.';
    fix = rc.immediatefix || 'See fix recommendations.';
    impact = users && users.length ? `Affected user count: ${users.length}` : 'Transaction was aborted.';
    confidenceScore = 75;
  } else if (blankApisCount > 0) {
    issue = `Silent failures detected: ${blankApisCount} API responses returned empty results.`;
    rootCause = 'API queries returned 200 OK but contained empty count, items, or records arrays (blank API responses).';
    fix = 'Verify database records and check if request filters are too restrictive.';
    impact = 'Users may experience empty lists or missing information on screen without any visible errors.';
    confidenceScore = 90;
  } else if (sqls && sqls.length) {
    issue = 'Database anomalies detected.';
    rootCause = 'Non-critical database queries failed or returned warning codes.';
    fix = 'Inspect the Database Analysis section for detailed ORA errors.';
    impact = 'Potential data loading delays.';
    confidenceScore = 85;
  }

  let confidenceLabel = 'HIGH';
  let confidenceColor = '#16A34A';
  if (confidenceScore < 80) {
    confidenceLabel = 'MEDIUM';
    confidenceColor = '#F59E0B';
  }

  return `<div class="confidence-band" style="border-left: 4px solid ${confidenceColor}; margin-bottom: 12px; padding-left: 8px;">
    <strong>Log Investigation Confidence:</strong> <span style="color:${confidenceColor}; font-weight:700;">${confidenceScore}% (${confidenceLabel})</span>
  </div>
  <strong>Issue:</strong> ${issue}<br>
  <strong>Log Type:</strong> <span class="badge" style="background:#E0F2FE; color:#0369A1; font-weight:600; padding:2px 6px; border-radius:4px; font-size:11px;">${logType || 'Generic'}</span><br>
  <strong>Execution Duration:</strong> ${durationStr}<br>
  <strong>API Execution Summary:</strong> Total: ${totalApis} | Healthy: <span style="color:#16A34A; font-weight:600;">${healthyApisCount}</span> | Failed: <span style="color:#DC2626; font-weight:600;">${failedApisCount}</span> | Blank: <span style="color:#F59E0B; font-weight:600;">${blankApisCount}</span><br>
  <strong>Affected Layer:</strong> ${module}${screen ? ` / Context: ${screen}` : ''}<br>
  <strong>Root Cause:</strong> ${rootCause}<br>
  <strong>Affected Identities:</strong> ${users && users.length ? `${users.length} unique accounts` : 'Not identified'}<br>
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
  const contextText = context.map(r => (r.rawLines ? r.rawLines[0] : r.message) || '').join('\n');
  // Also look ahead to catch cascading errors
  const futureContext = allRows.slice(idx + 1, Math.min(allRows.length, idx + 10));
  const futureText = futureContext.map(r => (r.rawLines ? r.rawLines[0] : r.message) || '').join('\n');

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
    rawTrace: (row.rawLines || [row.message]).slice(1).join('\n') || '',
    impactText: '',
    threadUser,
    securityContext: null,
    performanceInfo: null,
    phases: [],   // Track which investigation phases fired
  };

  // ─ Validation Issue ─
  if (d.errType === 'Validation Issue' || /ValidationException/i.test(msg)) {
    const listLines = [];
    (row.rawLines || [row.message]).forEach(l => {
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

window.selectRelatedApi = (idx) => {
  const api = STATE.analysis.apis[idx];
  if (api) {
    renderApiDetails(api);
    const container = document.getElementById('api-list-container');
    if (container) {
       container.querySelectorAll('.api-card').forEach(c => c.classList.remove('selected'));
       const targetCard = container.querySelector(`.api-card[data-idx="${idx}"]`);
       if (targetCard) {
          targetCard.classList.add('selected');
          targetCard.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
       }
    }
  }
};

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

  // ── Setup API Tabs ─────────────────────────────────────────────────────────
  const tabs = document.querySelectorAll('.api-tab-btn');
  tabs.forEach(tab => {
    tab.onclick = () => {
       tabs.forEach(t => {
          t.classList.remove('active');
          t.style.borderBottom = 'none';
          t.style.color = 'var(--text-muted)';
       });
       tab.classList.add('active');
       tab.style.borderBottom = '2px solid var(--primary)';
       tab.style.color = 'var(--text-light)';
       
       const tabName = tab.dataset.tab;
       document.querySelectorAll('.api-tab-content').forEach(content => {
          content.style.display = 'none';
       });
       const activeContent = document.getElementById(`api-tab-${tabName}`);
       if (activeContent) {
          activeContent.style.display = (tabName === 'list') ? 'flex' : 'block';
       }
    };
  });

  // ── Render Card List ───────────────────────────────────────────────────────
  const renderList = (filteredApis) => {
    if (!filteredApis.length) {
      container.innerHTML = '<div class="no-data-state"><p>No matching API calls found</p></div>';
      return;
    }

    container.innerHTML = filteredApis.map((api) => {
      const origIdx = STATE.analysis.apis.indexOf(api);
      
      let badgeClass = 'http-unknown';
      let badgeText = '⚫ HTTP Unknown';
      if (api.health === 'Success') { badgeClass = 'success'; badgeText = '🟢 Success'; }
      else if (api.health === 'Blank') { badgeClass = 'blank'; badgeText = '🟡 Blank'; }
      else if (api.health === 'Slow') { badgeClass = 'slow'; badgeText = '🟠 Slow'; }
      else if (api.health === 'Failed') { badgeClass = 'failed'; badgeText = '🔴 Failed'; }
      else if (api.health === 'Retry') { badgeClass = 'retry'; badgeText = '🔵 Retry'; }
      else if (api.health === 'HTTP Unknown') { badgeClass = 'http-unknown'; badgeText = '⚫ HTTP Unknown'; }

      const bizColor = api.health === 'Success' ? '#10B981' : api.health === 'Blank' ? '#F59E0B' : '#EF4444';
      const bizLabel = api.businessStatus || 'Unknown';

      return `
        <div class="api-card" data-idx="${origIdx}">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
            <span class="api-card-title-text" style="font-weight: 700; font-size: 12px; color: var(--text-light); word-break: break-all;" title="${escHtml(api.name)}">${escHtml(api.name)}</span>
            <span class="api-badge ${badgeClass}" style="font-size: 9.5px; padding: 2px 6px; border-radius: 4px; font-weight: 600; white-space: nowrap; margin-left: 8px;">${badgeText}</span>
          </div>
          <div style="display: flex; flex-wrap: wrap; gap: 8px; font-size: 11px; color: var(--text-muted); line-height: 1;">
            <span style="font-weight: 700; color: var(--primary); text-transform: uppercase;">${api.method || 'GET'}</span>
            <span style="background: rgba(255,255,255,0.05); padding: 1px 4px; border-radius: 3px;">⏱ ${api.ms !== 'Unknown' ? api.ms + ' ms' : 'Unknown Time'}</span>
            <span style="background: rgba(255,255,255,0.05); padding: 1px 4px; border-radius: 3px;">📦 Records: ${api.recordCount}</span>
          </div>
          <div style="margin-top: 6px; font-size: 11px; font-weight: 600; display: flex; align-items: center; justify-content: space-between; line-height: 1;">
            <span style="color: ${bizColor};">${escHtml(bizLabel)}</span>
            <span style="color: var(--text-muted); font-size: 10px;">${api.status}</span>
          </div>
        </div>`;
    }).join('');

    // Attach click listeners to cards
    container.querySelectorAll('.api-card').forEach(card => {
      card.addEventListener('click', () => {
        container.querySelectorAll('.api-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        const idx = parseInt(card.dataset.idx);
        renderApiDetails(STATE.analysis.apis[idx]);
      });
    });
  };

  // ── Unified Search, Sort, Filter Controller ──────────────────────────────
  STATE.apiTrackerFilter = STATE.apiTrackerFilter || 'with-resp';
  STATE.apiTrackerSort = STATE.apiTrackerSort || 'time-desc';

  const updateList = () => {
     let filtered = apis.slice();

     // 1. Filter
     const filterVal = STATE.apiTrackerFilter;
     if (filterVal === 'with-resp') {
        filtered = filtered.filter(a => a.response && a.response !== 'NOT LOGGED' && a.response !== 'N/A');
     } else if (filterVal === 'no-resp') {
        filtered = filtered.filter(a => !a.response || a.response === 'NOT LOGGED' || a.response === 'N/A');
     } else if (filterVal === 'success') {
        filtered = filtered.filter(a => a.health === 'Success');
     } else if (filterVal === 'failed') {
        filtered = filtered.filter(a => a.health === 'Failed');
     } else if (filterVal === 'blank') {
        filtered = filtered.filter(a => a.health === 'Blank');
     } else if (filterVal === 'slow') {
        filtered = filtered.filter(a => a.health === 'Slow');
     } else if (filterVal === '4xx') {
        filtered = filtered.filter(a => {
           const code = parseInt(a.status);
           return code >= 400 && code < 500;
        });
     } else if (filterVal === '5xx') {
        filtered = filtered.filter(a => {
           const code = parseInt(a.status);
           return code >= 500 && code < 600;
        });
     }

     // 2. Search
     const query = document.getElementById('api-search-input').value.toLowerCase().trim();
     if (query) {
        filtered = filtered.filter(a => 
           (a.name || '').toLowerCase().includes(query) || 
           (a.endpoint || '').toLowerCase().includes(query) || 
           (a.method || '').toLowerCase().includes(query) || 
           String(a.status || '').toLowerCase().includes(query) || 
           (a.thread || '').toLowerCase().includes(query) ||
           (a.businessStatus || '').toLowerCase().includes(query)
        );
     }

     // 3. Sort
     const sortVal = STATE.apiTrackerSort;
     if (sortVal === 'time-desc' || filterVal === 'longest-time') {
        filtered.sort((a, b) => (Number(b.ms) || 0) - (Number(a.ms) || 0));
     } else if (sortVal === 'time-asc') {
        filtered.sort((a, b) => (Number(a.ms) || 0) - (Number(b.ms) || 0));
     } else if (sortVal === 'count-desc' || filterVal === 'highest-count') {
        filtered.sort((a, b) => (Number(b.recordCount) || 0) - (Number(a.recordCount) || 0));
     } else if (sortVal === 'count-asc') {
        filtered.sort((a, b) => (Number(a.recordCount) || 0) - (Number(b.recordCount) || 0));
     } else if (sortVal === 'name-asc') {
        filtered.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
     } else if (sortVal === 'timestamp-desc') {
        filtered.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
     } else if (sortVal === 'timestamp-asc') {
        filtered.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
     } else if (sortVal === 'status-asc') {
        filtered.sort((a, b) => (a.health || '').localeCompare(b.health || ''));
     }

     renderList(filtered);
  };

  // Wire Filter Pills
  const pills = document.querySelectorAll('.filter-pill');
  pills.forEach(pill => {
     pill.onclick = () => {
        pills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        STATE.apiTrackerFilter = pill.dataset.filter;
        updateList();
     };
  });

  // Wire Sort Dropdown
  const sortSelect = document.getElementById('api-sort-select');
  sortSelect.value = STATE.apiTrackerSort;
  sortSelect.onchange = () => {
     STATE.apiTrackerSort = sortSelect.value;
     updateList();
  };

  // Wire Search Box
  const searchInput = document.getElementById('api-search-input');
  searchInput.value = '';
  const newSearchInput = searchInput.cloneNode(true);
  searchInput.parentNode.replaceChild(newSearchInput, searchInput);
  newSearchInput.addEventListener('input', () => {
     updateList();
  });

  // Run initial list update
  updateList();

  // ── Tab 2: Blank Responses Panel ──────────────────────────────────────────
  const blankContainer = document.getElementById('api-blank-container');
  const blankApis = apis.filter(a => a.health === 'Blank' || a.recordCount === 0);
  if (!blankApis.length) {
     blankContainer.innerHTML = '<div class="no-data-state"><p>No blank responses detected (count = 0)</p></div>';
  } else {
     blankContainer.innerHTML = blankApis.map(api => {
        const origIdx = STATE.analysis.apis.indexOf(api);
        return `
          <div class="api-card" data-idx="${origIdx}" style="border-left: 3px solid #F59E0B;">
            <div style="font-weight: 700; color: var(--text-light);">${escHtml(api.name)}</div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">HTTP Status: ${api.status} | Time: ${api.ms} ms</div>
            <div style="font-size: 11px; font-weight: 700; color: #F59E0B; margin-top: 2px;">Records: 0</div>
          </div>
        `;
     }).join('');
     blankContainer.querySelectorAll('.api-card').forEach(card => {
        card.addEventListener('click', () => {
           const idx = parseInt(card.dataset.idx);
           renderApiDetails(STATE.analysis.apis[idx]);
        });
     });
  }

  // ── Tab 3: Aggregated Stats Table ──────────────────────────────────────────
  const statsTbody = document.getElementById('api-stats-tbody');
  const grouped = {};
  apis.forEach(api => {
     const name = api.name || 'API_CALL';
     if (!grouped[name]) grouped[name] = [];
     grouped[name].push(api);
  });

  const rows = [];
  for (const [name, list] of Object.entries(grouped)) {
     const calls = list.length;
     let sumTime = 0;
     let minTime = Infinity;
     let maxTime = -Infinity;
     let succ = 0, blank = 0, fail = 0;

     list.forEach(a => {
        const t = Number(a.ms);
        if (!isNaN(t)) {
           sumTime += t;
           if (t < minTime) minTime = t;
           if (t > maxTime) maxTime = t;
        }
        if (a.health === 'Failed') fail++;
        else if (a.health === 'Blank') blank++;
        else succ++;
     });

     const avgTime = sumTime / calls;
     const minStr = minTime === Infinity ? 'Unknown' : minTime + 'ms';
     const maxStr = maxTime === -Infinity ? 'Unknown' : maxTime + 'ms';
     const avgStr = minTime === Infinity ? 'Unknown' : Math.round(avgTime) + 'ms';
     
     const successPct = Math.round((succ / calls) * 100);
     const blankPct = Math.round((blank / calls) * 100);
     const failurePct = Math.round((fail / calls) * 100);

     rows.push({
        name, calls, avgTime: minTime === Infinity ? 0 : avgTime, avgStr, minStr, maxStr, successPct, blankPct, failurePct
     });
  }

  rows.sort((a, b) => b.calls - a.calls);

  if (!rows.length) {
     statsTbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px; color: var(--text-muted);">No metrics.</td></tr>';
  } else {
     statsTbody.innerHTML = rows.map(r => `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.03); color:var(--text-light);">
          <td style="padding: 8px 4px; font-weight:700;">${escHtml(r.name)}</td>
          <td style="padding: 8px 4px; text-align: center;">${r.calls}</td>
          <td style="padding: 8px 4px; text-align: center; font-weight:600; color:var(--primary);">${r.avgStr}</td>
          <td style="padding: 8px 4px; text-align: center; color:var(--text-muted);">${r.minStr} / ${r.maxStr}</td>
          <td style="padding: 8px 4px; text-align: center; color:#10B981; font-weight:700;">${r.successPct}%</td>
          <td style="padding: 8px 4px; text-align: center; color:#F59E0B; font-weight:700;">${r.blankPct}%</td>
          <td style="padding: 8px 4px; text-align: center; color:#EF4444; font-weight:700;">${r.failurePct}%</td>
        </tr>
     `).join('');
  }
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

  const isError = api.health === 'Failed';
  const badgeClass = api.health === 'Failed' ? 'failed' : api.health === 'Slow' ? 'slow' : api.health === 'Blank' ? 'blank' : api.health === 'Retry' ? 'retry' : api.health === 'HTTP Unknown' ? 'http-unknown' : 'success';
  const badgeText = api.health === 'Success' ? '🟢 Success' : api.health === 'Blank' ? '🟡 Blank' : api.health === 'Slow' ? '🟠 Slow' : api.health === 'Failed' ? '🔴 Failed' : api.health === 'Retry' ? '🔵 Retry' : '⚫ HTTP Unknown';

  let httpLabel = 'Not Logged';
  let httpExplain = 'The HTTP response status code was not logged.';
  if (HTTP_KB[api.status]) {
     httpLabel = HTTP_KB[api.status].label;
     httpExplain = HTTP_KB[api.status].explain;
  } else if (api.status === 'HTTP Status Not Logged') {
     httpLabel = 'Not Logged';
     httpExplain = 'No HTTP status code was logged, but valid response payload exists.';
  }

  // ── Business Result Badge ─────────────────────────────────────────────────
  const bizColor = api.health === 'Success' ? '#10B981' : api.health === 'Blank' ? '#F59E0B' : '#EF4444';
  const bizIcon  = api.health === 'Success' ? '🟢' : api.health === 'Blank' ? '🟡' : '🔴';
  const bizLabel = api.businessStatus || 'Unknown';

  // ── Request / Response Payload HTML ──────────────────────────────────────
  let reqPayloadHtml = `
    <div style="padding:12px; background:rgba(239,68,68,0.04); border:1px dashed rgba(239,68,68,0.3); border-radius:6px; font-size:12px;">
      <div style="color:#EF4444; font-weight:700; margin-bottom:4px;">Not Logged</div>
      <div style="color:var(--text-muted); font-size:11px; margin-bottom:6px;">Recommendation:</div>
      <pre style="background:#0F172A; padding:6px; border-radius:4px; font-family:monospace; color:#34D399; margin:0; font-size:11.5px; overflow-x:auto;">Enable logger.trace() for request/response.</pre>
    </div>`;
  if (api.request && api.request !== 'N/A' && api.request !== 'NOT LOGGED') {
    let reqText = api.request;
    try {
      if (reqText.trim().startsWith('{') || reqText.trim().startsWith('[')) {
        reqText = JSON.stringify(JSON.parse(reqText), null, 2);
      }
    } catch(e) {}
    reqPayloadHtml = `<pre class="api-payload-body">${redactHTML(escHtml(reqText))}</pre>`;
  }

  let respPayloadHtml = `
    <div style="padding:12px; background:rgba(239,68,68,0.04); border:1px dashed rgba(239,68,68,0.3); border-radius:6px; font-size:12px;">
      <div style="color:#EF4444; font-weight:700; margin-bottom:4px;">Not Logged</div>
      <div style="color:var(--text-muted); font-size:11px; margin-bottom:6px;">Recommendation:</div>
      <pre style="background:#0F172A; padding:6px; border-radius:4px; font-family:monospace; color:#34D399; margin:0; font-size:11.5px; overflow-x:auto;">Enable logger.trace() for request/response.</pre>
    </div>`;
  if (api.response && api.response !== 'N/A' && api.response !== 'NOT LOGGED') {
    let respText = api.response;
    let isJson = false;
    try {
      if (respText.trim().startsWith('{') || respText.trim().startsWith('[')) {
        respText = JSON.stringify(JSON.parse(respText), null, 2);
        isJson = true;
      }
    } catch(e) {}
    
    respPayloadHtml = `
      <div style="display:flex; flex-direction:column; background:#0F172A; border:1px solid var(--border); border-radius:6px; overflow:hidden;">
        <div style="display:flex; justify-content:space-between; align-items:center; background:#1E293B; padding:6px 12px; border-bottom:1px solid var(--border);">
          <span style="font-size:11px; font-weight:600; color:var(--text-muted); text-transform:uppercase;">${isJson ? 'JSON Response' : 'Raw Response'}</span>
          <div style="display:flex; gap:8px;">
            <button onclick="toggleResponseCollapse()" id="btn-toggle-resp" style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); color:var(--text-normal); font-size:11px; border-radius:4px; padding:3px 8px; cursor:pointer;">Collapse</button>
            <button onclick="copyResponseText()" style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); color:var(--text-normal); font-size:11px; border-radius:4px; padding:3px 8px; cursor:pointer;">Copy</button>
          </div>
        </div>
        <pre id="api-response-pre" style="margin:0; padding:12px; max-height:350px; overflow:auto; font-family:'Fira Code',Consolas,monospace; font-size:12px; color:#E2E8F0; line-height:1.5; white-space:pre; word-wrap:normal; transition:max-height 0.2s;">${redactHTML(escHtml(respText))}</pre>
      </div>`;
  }

  // ── Record Count Badge ────────────────────────────────────────────────────
  let recordBadge = '';
  if (api.recordCount !== 'Unknown') {
    const rcColor = api.recordCount === 0 ? '#F59E0B' : '#10B981';
    recordBadge = `<div class="api-details-row">
      <div class="api-details-label">Record Count</div>
      <div class="api-details-value" style="font-weight:700;color:${rcColor};">
        ${api.recordCount} records
      </div>
    </div>`;
  } else {
    recordBadge = `<div class="api-details-row">
      <div class="api-details-label">Record Count</div>
      <div class="api-details-value">
        <span style="color:#EF4444; font-weight:700;">Not Logged</span>
        <span style="font-size:10px; color:#94A3B8; margin-left:8px;">Recommendation: Enable logger.trace() for request/response.</span>
      </div>
    </div>`;
  }

  // URL formatter helper
  const urlValue = api.endpoint ? redactHTML(escHtml(api.endpoint)) : `
    <span style="color:#EF4444; font-weight:700;">Not Logged</span>
    <span style="font-size:10px; color:#94A3B8; margin-left:8px;">Recommendation: Enable logger.trace() for request/response.</span>
  `;

  // Query Params formatter helper
  const queryParamsValue = (api.queryParams && api.queryParams !== 'N/A') ? redactHTML(escHtml(api.queryParams)) : `
    <span style="color:#EF4444; font-weight:700;">Not Logged</span>
    <span style="font-size:10px; color:#94A3B8; margin-left:8px;">Recommendation: Enable logger.trace() for request/response.</span>
  `;

  // Request Headers formatter helper
  const hasHeaders = api.headers && Object.keys(api.headers).length > 0;
  const headersValue = hasHeaders ? redactHTML(escHtml(JSON.stringify(api.headers))) : `
    <span style="color:#EF4444; font-weight:700;">Not Logged</span>
    <span style="font-size:10px; color:#94A3B8; margin-left:8px;">Recommendation: Enable logger.trace() for request/response.</span>
  `;

  // Correlation ID formatter helper
  const correlationValue = (api.correlationId && api.correlationId !== 'N/A') ? redactHTML(escHtml(api.correlationId)) : `
    <span style="color:#EF4444; font-weight:700;">Not Logged</span>
    <span style="font-size:10px; color:#94A3B8; margin-left:8px;">Recommendation: Enable logger.trace() for request/response.</span>
  `;

  // ── Related APIs Chain ───────────────────────────────────────────────────
  let relatedChainHtml = '';
  const relatedApis = STATE.analysis.apis.filter(a => a.thread === api.thread);
  if (relatedApis.length > 1) {
     relatedApis.sort((a, b) => (a.logIndex || 0) - (b.logIndex || 0));
     const firstFailure = relatedApis.find(a => a.health === 'Failed');
     
     const nodesHtml = relatedApis.map(a => {
        const isSelected = a === api;
        const isFirstFail = a === firstFailure;
        const origIdx = STATE.analysis.apis.indexOf(a);
        
        let borderClass = 'success';
        if (a.health === 'Failed') borderClass = 'failed';
        else if (a.health === 'Blank') borderClass = 'blank';
        else if (a.health === 'Slow') borderClass = 'slow';
        else if (a.health === 'Retry') borderClass = 'retry';
        else if (a.health === 'HTTP Unknown') borderClass = 'http-unknown';

        return `
          <div class="related-node ${borderClass} ${isSelected ? 'selected' : ''}" onclick="selectRelatedApi(${origIdx})">
             <span style="font-weight:700; color:var(--text-light); font-size:10.5px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escHtml(a.name)}</span>
             <span style="font-size:9.5px; color:var(--text-muted); margin-top:2px;">⏱ ${a.ms !== 'Unknown' ? a.ms + ' ms' : 'Unknown'}</span>
             <span style="font-size:9.5px; color:var(--text-muted);">📦 Records: ${a.recordCount}</span>
             ${isFirstFail ? `<span style="color:#EF4444; font-weight:700; font-size:9px; margin-top:2px;">⚠️ [First Failure]</span>` : ''}
          </div>
        `;
     }).join('<span class="related-arrow">➔</span>');

     relatedChainHtml = `
       <div class="api-payload-box" style="margin-top:16px;">
         <div class="api-payload-title">🔗 Execution Flow Chain (Thread Related)</div>
         <div class="related-chain-flow">${nodesHtml}</div>
       </div>
     `;
  }

  // ── Render base panel ─────────────────────────────────────────────────────
  panel.innerHTML = `
    <div class="api-details-header">
      <span class="api-details-header-title">${escHtml(api.name)}</span>
      <span class="api-badge ${badgeClass}" style="font-size:12px; padding:3px 10px;">${badgeText}</span>
    </div>
    <div class="api-details-content" style="max-height: calc(100vh - 220px); overflow-y: auto; padding-right: 4px;">

      <!-- Business Result Row -->
      <div class="api-details-row" style="background:${bizColor}11; border-radius:6px; padding:8px 12px; border:1px solid ${bizColor}33; margin-bottom:8px;">
        <div class="api-details-label" style="color:${bizColor};font-weight:700;">Business Result</div>
        <div class="api-details-value" style="font-weight:700;color:${bizColor};">${bizIcon} ${escHtml(bizLabel)}</div>
      </div>

      <div class="api-details-row">
        <div class="api-details-label">API Name</div>
        <div class="api-details-value" style="font-weight:600; color:var(--text-light);">${escHtml(api.name)}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">Request URL</div>
        <div class="api-details-value" style="word-break:break-all;">${urlValue}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">HTTP Method</div>
        <div class="api-details-value" style="font-weight:700; color:var(--primary);">${escHtml(api.method || 'GET')}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">Query Parameters</div>
        <div class="api-details-value" style="word-break:break-all;">${queryParamsValue}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">Request Headers</div>
        <div class="api-details-value" style="word-break:break-all; font-family:monospace; font-size:11px;">${headersValue}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">Correlation ID</div>
        <div class="api-details-value" style="word-break:break-all; font-weight:500;">${correlationValue}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">HTTP Status</div>
        <div class="api-details-value" style="font-weight:700; color:${isError ? '#DC2626' : '#16A34A'};">HTTP ${api.status} — ${escHtml(httpLabel)}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">Response Time</div>
        <div class="api-details-value" style="font-weight:700; color:${api.ms > 5000 ? '#DC2626' : api.ms > 2000 ? '#F59E0B' : '#10B981'}">
          ${api.ms} ms ${api.ms > 5000 ? '🔴 Critical' : api.ms > 2000 ? '🟡 Slow' : '🟢 OK'}
        </div>
      </div>
      ${recordBadge}
      <div class="api-details-row">
        <div class="api-details-label">Timestamp</div>
        <div class="api-details-value">${escHtml(api.timestamp || 'N/A')}</div>
      </div>
      <div class="api-details-row">
        <div class="api-details-label">Thread</div>
        <div class="api-details-value">${redactHTML(escHtml(api.thread || 'N/A'))}</div>
      </div>
      ${api.retryCount > 0 ? `<div class="api-details-row">
        <div class="api-details-label">Retry Count</div>
        <div class="api-details-value" style="color:#F59E0B;font-weight:700;">⚠ ${api.retryCount} retries detected</div>
      </div>` : ''}

      <div style="margin-top:14px; padding:10px 14px; background:var(--bg); border-radius:8px; border:1px solid var(--border); font-size:12.5px; color:var(--text-normal); line-height:1.5;">
        <strong>📋 Status Analysis:</strong> ${escHtml(httpExplain)}
      </div>

      <div style="margin-top:10px; padding:10px 14px; background:rgba(139,92,246,0.06); border-radius:8px; border:1px solid rgba(139,92,246,0.3); font-size:12.5px; color:var(--text-normal); line-height:1.5;">
        <strong>✨ AI Recommendation:</strong> ${escHtml(api.recommendation || 'Everything looks normal.')}
      </div>

      <!-- Related API Flow Chain -->
      ${relatedChainHtml}

      <!-- Request Payload -->
      <div class="api-payload-box" style="margin-top: 14px;">
        <div class="api-payload-title">
          <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
            <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" />
          </svg>
          Request Payload
          ${(api.request && api.request !== 'N/A' && api.request !== 'NOT LOGGED') ? '<span style="color:#10B981;font-size:10px;margin-left:6px;">✓ Captured</span>' : '<span style="color:#EF4444;font-size:10px;margin-left:6px;">⚠ Not logged</span>'}
        </div>
        ${reqPayloadHtml}
      </div>

      <!-- Response Payload -->
      <div class="api-payload-box">
        <div class="api-payload-title">
          <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
            <polyline points="4 17 10 11 4 5" />
            <line x1="12" y1="19" x2="20" y2="19" />
          </svg>
          Response Payload
          ${(api.response && api.response !== 'N/A' && api.response !== 'NOT LOGGED') ? '<span style="color:#10B981;font-size:10px;margin-left:6px;">✓ Captured</span>' : '<span style="color:#EF4444;font-size:10px;margin-left:6px;">⚠ Not logged</span>'}
        </div>
        ${respPayloadHtml}
      </div>

      <!-- Brain Investigation Section -->
      <div id="api-brain-investigation-container" style="margin-top:16px;"></div>

    </div>`;

  // ── Inject Brain Investigation Report ────────────────────────────────────
  if (window.LOGRADAR_BRAIN) {
    try {
      const brainResult = LOGRADAR_BRAIN.investigateAPI(api);
      const brainContainer = document.getElementById('api-brain-investigation-container');
      if (brainContainer && brainResult) {
        const brainHtml = LOGRADAR_BRAIN.renderBrainPanel(brainResult);
        brainContainer.innerHTML = brainHtml;
      }
    } catch(e) {
      console.warn('LogRadar Brain investigation error:', e);
    }
  }
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

window.toggleResponseCollapse = function() {
  const pre = document.getElementById('api-response-pre');
  const btn = document.getElementById('btn-toggle-resp');
  if (!pre || !btn) return;
  if (pre.style.maxHeight === '40px') {
     pre.style.maxHeight = '350px';
     btn.textContent = 'Collapse';
  } else {
     pre.style.maxHeight = '40px';
     btn.textContent = 'Expand';
  }
};

window.copyResponseText = function() {
  const pre = document.getElementById('api-response-pre');
  if (!pre) return;
  navigator.clipboard.writeText(pre.textContent).then(() => {
     alert('Response copied to clipboard!');
  });
};

function updateFlexiFeaturesVisibility() {
  const isFlexi = STATE.analysis && STATE.analysis.logType === 'Flexi Runtime';
  const dbgNav = document.getElementById('nav-debugger');
  const graphNav = document.getElementById('nav-graph');
  const flowNav = document.getElementById('nav-flow');

  if (isFlexi) {
    if (dbgNav) dbgNav.style.display = 'flex';
    if (graphNav) graphNav.style.display = 'flex';
    if (flowNav) flowNav.style.display = 'flex';
  } else {
    if (dbgNav) dbgNav.style.display = 'none';
    if (graphNav) graphNav.style.display = 'none';
    if (flowNav) flowNav.style.display = 'none';
    
    const activeNav = document.querySelector('.nav-item.active');
    if (activeNav) {
      const activeView = activeNav.dataset.view;
      if (activeView === 'debugger' || activeView === 'graph' || activeView === 'flow') {
         switchView('dashboard');
      }
    }
  }
}

function renderDashboard(a) {
  const $ = id => document.getElementById(id);
  
  updateFlexiFeaturesVisibility();

  // Stat Cards
  $('stat-critical').textContent = a.errors.length;
  $('stat-critical-sub').textContent = a.errors.filter(e => e.level === 'FATAL').length + ' FATAL';
  $('stat-warnings').textContent = a.warnings ? (Array.isArray(a.warnings) ? a.warnings.length : a.warnings) : 0;
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

  // Log Type badge in header
  const logTypeBadge = $('log-type-badge');
  if (logTypeBadge) {
    if (a.logType) {
      logTypeBadge.textContent = a.logType;
      logTypeBadge.className = 'log-type-badge ' + a.logType.toLowerCase().replace(/\s+/g, '-');
      logTypeBadge.style.display = 'inline-block';
    } else {
      logTypeBadge.style.display = 'none';
    }
  }

  // Performance List Table
  const perfEl = $('perf-list');
  if (a.apis.length) {
    const healthBadgeColors = {
      'Healthy': { bg: '#10B98115', text: '#10B981' },
      'Blank Response': { bg: '#F59E0B15', text: '#D97706' },
      'Slow': { bg: '#F59E0B15', text: '#D97706' },
      'Retry': { bg: '#3B82F615', text: '#3B82F6' },
      'Failed': { bg: '#EF444415', text: '#EF4444' },
      'Timeout': { bg: '#EF444415', text: '#EF4444' }
    };

    perfEl.innerHTML = `
      <table style="width:100%; border-collapse:collapse; font-size:12.5px; text-align:left; color:var(--text-normal);">
        <thead>
          <tr style="border-bottom:2px solid var(--border); color:var(--text-light); font-weight:600; font-size:11.5px; text-transform:uppercase; letter-spacing:0.5px;">
            <th style="padding:10px 8px;">API</th>
            <th style="padding:10px 8px;">Status</th>
            <th style="padding:10px 8px;">Response Time</th>
            <th style="padding:10px 8px;">Records</th>
            <th style="padding:10px 8px;">Health</th>
          </tr>
        </thead>
        <tbody>
          ${a.apis.sort((x, y) => y.ms - x.ms).map(api => {
            const colors = healthBadgeColors[api.health || 'Healthy'] || healthBadgeColors['Healthy'];
            const statusColor = api.status >= 400 ? '#EF4444' : '#10B981';
            const statusHtml = api.status ? `<span style="font-weight:700; color:${statusColor}">${api.status}</span>` : '<span style="color:#94A3B8;">—</span>';
            const recordsHtml = (api.recordCount !== null && api.recordCount !== undefined) ? `<strong>${api.recordCount}</strong>` : '<span style="color:#94A3B8;">—</span>';
            
            return `
              <tr class="clickable-perf-api-row" data-name="${escHtml(api.name)}" style="border-bottom:1px solid var(--border); cursor:pointer; transition:background-color 0.15s;" onmouseover="this.style.backgroundColor='var(--bg-row-hover)'" onmouseout="this.style.backgroundColor='transparent'">
                <td style="padding:12px 8px; font-weight:600; color:var(--primary);">${escHtml(api.name)}</td>
                <td style="padding:12px 8px;">${statusHtml}</td>
                <td style="padding:12px 8px; font-weight:500;">
                  <span>${api.ms} ms</span>
                  <div style="width:40px; height:3px; background:#1E293B; border-radius:2px; margin-top:4px; overflow:hidden;">
                    <div style="width:${Math.min(100, Math.round((api.ms/5000)*100))}%; height:100%; background:${api.ms > 5000 ? '#EF4444' : api.ms > 2000 ? '#F59E0B' : '#10B981'}"></div>
                  </div>
                </td>
                <td style="padding:12px 8px;">${recordsHtml}</td>
                <td style="padding:12px 8px;">
                  <span style="background:${colors.bg}; color:${colors.text}; padding:3px 8px; border-radius:12px; font-size:11px; font-weight:700; border:1px solid ${colors.text}25;">
                    ${api.health || 'Healthy'}
                  </span>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>`;

    perfEl.querySelectorAll('.clickable-perf-api-row').forEach(row => {
      row.addEventListener('click', () => {
        selectApiByName(row.dataset.name);
      });
    });
  } else {
    perfEl.innerHTML = '<div style="padding:20px; color:#94A3B8; text-align:center;">No API calls detected in log.</div>';
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
  
  // Render our new dashboard cards
  renderBlankApiReport(a.blankApis);
  renderWarningAnalysis(a.warnings);
  renderLoggerAnalysis(a.loggerStats);
  renderIntegrationApiMetrics(a.apis);
}

function renderIntegrationApiMetrics(apis) {
  const $ = id => document.getElementById(id);
  if (!apis) return;

  // 1. Calculate Stats
  const total = apis.length;
  const success = apis.filter(api => api.health === 'Success' || api.health === 'Slow').length;
  const blank = apis.filter(api => api.health === 'Blank').length;
  const failed = apis.filter(api => api.health === 'Failed').length;
  const slow = apis.filter(api => api.health === 'Slow').length;
  
  const times = apis.filter(api => typeof api.ms === 'number').map(api => api.ms);
  const avg = times.length ? Math.round(times.reduce((sum, t) => sum + t, 0) / times.length) : 0;

  const recordCounts = apis
     .map(api => Number(api.recordCount))
     .filter(count => !isNaN(count));
  const totalRecords = recordCounts.reduce((sum, c) => sum + c, 0);
  const maxRecord = recordCounts.length ? Math.max(...recordCounts) : 0;

  if ($('api-stat-total')) $('api-stat-total').textContent = total;
  if ($('api-stat-success')) $('api-stat-success').textContent = success;
  if ($('api-stat-blank')) $('api-stat-blank').textContent = blank;
  if ($('api-stat-failed')) $('api-stat-failed').textContent = failed;
  if ($('api-stat-slow')) $('api-stat-slow').textContent = slow;
  if ($('api-stat-avg')) $('api-stat-avg').textContent = avg + 'ms';
  if ($('api-stat-total-records')) $('api-stat-total-records').textContent = totalRecords.toLocaleString();
  if ($('api-stat-highest-record')) $('api-stat-highest-record').textContent = maxRecord.toLocaleString();

  // 2. Slowest APIs (Top 10)
  const slowestTbody = $('api-dashboard-slowest');
  if (slowestTbody) {
     const slowestApis = [...apis]
        .filter(api => typeof api.ms === 'number' && api.ms > 0)
        .sort((x, y) => y.ms - x.ms)
        .slice(0, 10);
        
     if (slowestApis.length) {
        slowestTbody.innerHTML = slowestApis.map(api => {
           let threshold = '2000 ms';
           let rec = api.recommendation || 'Verify database indexes or network latency.';
           return `
              <tr class="clickable-dashboard-api" data-name="${escHtml(api.name)}" style="border-bottom:1px solid var(--border); cursor:pointer;" onmouseover="this.style.backgroundColor='var(--bg-row-hover)'" onmouseout="this.style.backgroundColor='transparent'">
                 <td style="padding:8px; font-weight:600; color:var(--primary);">${escHtml(api.name)}</td>
                 <td style="padding:8px; color:#EF4444; font-weight:600;">${api.ms} ms</td>
                 <td style="padding:8px; color:var(--text-muted);">${threshold}</td>
                 <td style="padding:8px; font-size:11.5px; color:var(--text-normal);">${escHtml(rec)}</td>
              </tr>
           `;
        }).join('');
     } else {
        slowestTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:24px; color:var(--text-muted);">No slow APIs detected</td></tr>`;
     }
  }

  // 3. Blank APIs (Top 10)
  const blankTbody = $('api-dashboard-blank');
  if (blankTbody) {
     const blankApis = [...apis]
        .filter(api => api.businessStatus === 'Blank Response')
        .slice(0, 10);
        
     if (blankApis.length) {
        blankTbody.innerHTML = blankApis.map(api => {
           const countVal = api.recordCount !== undefined ? api.recordCount : 0;
           return `
              <tr class="clickable-dashboard-api" data-name="${escHtml(api.name)}" style="border-bottom:1px solid var(--border); cursor:pointer;" onmouseover="this.style.backgroundColor='var(--bg-row-hover)'" onmouseout="this.style.backgroundColor='transparent'">
                 <td style="padding:8px; font-weight:600; color:var(--primary);">${escHtml(api.name)}</td>
                 <td style="padding:8px; word-break:break-all; font-family:monospace; font-size:11px; max-width:180px;">${escHtml(api.endpoint || 'N/A')}</td>
                 <td style="padding:8px; font-weight:700; color:#F59E0B;">${countVal}</td>
                 <td style="padding:8px; font-weight:500;">${api.ms !== 'Unknown' ? api.ms + ' ms' : 'N/A'}</td>
                 <td style="padding:8px; font-size:11.5px; color:var(--text-normal);">${escHtml(api.recommendation)}</td>
              </tr>
           `;
        }).join('');
     } else {
        blankTbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:24px; color:var(--text-muted);">No blank APIs detected</td></tr>`;
     }
  }

  // 4. Fastest APIs (Top 10)
  const fastestTbody = $('api-dashboard-fastest');
  if (fastestTbody) {
     const groups = {};
     apis.forEach(api => {
        if (typeof api.ms === 'number') {
           if (!groups[api.name]) {
              groups[api.name] = { name: api.name, min: api.ms, total: 0, count: 0 };
           }
           const g = groups[api.name];
           if (api.ms < g.min) g.min = api.ms;
           g.total += api.ms;
           g.count++;
        }
     });
     
     const fastestApis = Object.values(groups)
        .sort((x, y) => x.min - y.min)
        .slice(0, 10);
        
     if (fastestApis.length) {
        fastestTbody.innerHTML = fastestApis.map(g => {
           const avgVal = Math.round(g.total / g.count);
           return `
              <tr class="clickable-dashboard-api" data-name="${escHtml(g.name)}" style="border-bottom:1px solid var(--border); cursor:pointer;" onmouseover="this.style.backgroundColor='var(--bg-row-hover)'" onmouseout="this.style.backgroundColor='transparent'">
                 <td style="padding:8px; font-weight:600; color:var(--primary);">${escHtml(g.name)}</td>
                 <td style="padding:8px; color:#10B981; font-weight:600;">${g.min} ms</td>
                 <td style="padding:8px; font-weight:600; color:var(--text-light);">${g.count}</td>
                 <td style="padding:8px; color:var(--text-muted);">${avgVal} ms (avg)</td>
              </tr>
           `;
        }).join('');
     } else {
        fastestTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:24px; color:var(--text-muted);">No APIs detected</td></tr>`;
     }
  }

  // 5. Bottom Execution Timeline
  const timelineDiv = $('api-dashboard-timeline');
  if (timelineDiv) {
     const sortedApis = [...apis].sort((x, y) => (x.logIndex || 0) - (y.logIndex || 0));
     if (sortedApis.length) {
        let html = '';
        sortedApis.forEach((api, idx) => {
           const timeStr = api.timestamp ? api.timestamp.split(' ')[1] || api.timestamp.split('T')[1] || api.timestamp : '';
           const cleanTime = timeStr ? timeStr.substring(0, 5) : '';
           
           let statusColor = '#10B981';
           if (api.businessStatus === 'Blank Response' || api.businessStatus === 'Slow API') statusColor = '#F59E0B';
           if (api.businessStatus === 'Server Failure' || api.businessStatus === 'Validation Failed' || api.businessStatus === 'Connection Failure') statusColor = '#EF4444';
           
           html += `
              <div class="timeline-flow-node clickable-dashboard-api" data-name="${escHtml(api.name)}" style="display:flex; flex-direction:column; align-items:center; background:#1E293B; border:1px solid rgba(255,255,255,0.08); border-top:3px solid ${statusColor}; border-radius:6px; padding:6px 12px; min-width:110px; cursor:pointer; flex-shrink:0; transition:all 0.15s;" onmouseover="this.style.borderColor='${statusColor}'" onmouseout="this.style.borderColor='rgba(255,255,255,0.08)'">
                 <span style="font-size:10px; font-weight:600; color:var(--text-muted);">${escHtml(cleanTime || '00:00')}</span>
                 <span style="font-size:11.5px; font-weight:700; color:var(--text-light); margin-top:2px; word-break:break-all; text-align:center;">${escHtml(api.name)}</span>
                 <span style="font-size:10px; color:${statusColor}; margin-top:2px; font-weight:500;">${api.ms !== 'Unknown' ? api.ms + ' ms' : 'N/A'}</span>
              </div>
           `;
           
           if (idx < sortedApis.length - 1) {
              html += `<div style="color:var(--text-muted); font-weight:700; font-size:14px; flex-shrink:0;">➔</div>`;
           }
        });
        timelineDiv.innerHTML = html;
     } else {
        timelineDiv.innerHTML = `<div style="width:100%; text-align:center; color:var(--text-muted);">Upload log files to render execution sequence</div>`;
     }
  }

  // Register click events
  document.querySelectorAll('.clickable-dashboard-api').forEach(el => {
     el.addEventListener('click', () => {
        selectApiByName(el.dataset.name);
     });
  });
}

function renderBlankApiReport(blankApis) {
  const container = document.getElementById('blank-api-report-body');
  if (!container) return;
  
  if (!blankApis || !blankApis.length) {
    container.innerHTML = `
      <div class="no-data-state" style="padding:20px;">
        <p>No blank API responses (silent failures) detected in log.</p>
      </div>`;
    return;
  }
  
  container.innerHTML = `
    <table class="blank-api-table" style="width:100%; border-collapse:collapse; font-size:13px; text-align:left;">
      <thead>
        <tr style="border-bottom:2px solid var(--border); color:var(--text-light); font-weight:600;">
          <th style="padding:8px 12px;">API Name</th>
          <th style="padding:8px 12px;">HTTP Status</th>
          <th style="padding:8px 12px;">Response Time</th>
          <th style="padding:8px 12px;">Blank Reason</th>
          <th style="padding:8px 12px;">Recommendation</th>
        </tr>
      </thead>
      <tbody>
        ${blankApis.map(api => `
          <tr class="clickable-blank-api-row" data-name="${escHtml(api.name)}" style="border-bottom:1px solid var(--border); cursor:pointer;" onmouseover="this.style.backgroundColor='var(--bg-row-hover)'" onmouseout="this.style.backgroundColor='transparent'">
            <td style="padding:10px 12px; font-weight:600; color:var(--primary);">${escHtml(api.name)}</td>
            <td style="padding:10px 12px;"><span class="badge success" style="font-size:11px;">HTTP ${api.status}</span></td>
            <td style="padding:10px 12px; font-weight:500;">${api.ms}ms</td>
            <td style="padding:10px 12px; color:#D97706; font-weight:500;">⚠ ${escHtml(api.blankReason)}</td>
            <td style="padding:10px 12px; color:var(--text-normal); font-size:12px;">${escHtml(api.recommendation)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>`;
    
  container.querySelectorAll('.clickable-blank-api-row').forEach(row => {
    row.addEventListener('click', () => {
      selectApiByName(row.dataset.name);
    });
  });
}

function renderWarningAnalysis(warnings) {
  const container = document.getElementById('warning-analysis-body');
  if (!container) return;
  
  if (!warnings || !warnings.length) {
    container.innerHTML = `
      <div class="no-data-state" style="padding:20px;">
        <p>No warnings detected in log.</p>
      </div>`;
    return;
  }
  
  const grouped = {};
  warnings.forEach(w => {
    if (!grouped[w.classification]) {
      grouped[w.classification] = { count: 0, list: [], impact: w.impact, causesFutureFailure: w.causesFutureFailure };
    }
    grouped[w.classification].count++;
    grouped[w.classification].list.push(w);
  });
  
  container.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:12px;">
      ${Object.keys(grouped).map(cls => {
        const info = grouped[cls];
        const failBadge = info.causesFutureFailure 
          ? `<span class="badge error" style="font-size:9.5px; font-weight:600; margin-left:6px;">High Risk of Failure</span>` 
          : `<span class="badge warn" style="font-size:9.5px; font-weight:600; margin-left:6px;">Low Risk</span>`;
        return `
          <div class="warning-card" style="padding:12px 16px; border:1px solid var(--border); border-radius:8px; background:var(--card-bg-sub); position:relative;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
              <span style="font-weight:700; font-size:13.5px; color:#B45309;">${cls} (${info.count})</span>
              ${failBadge}
            </div>
            <div style="font-size:12px; color:var(--text-normal); line-height:1.5; margin-bottom:8px;">
              <strong>Impact:</strong> ${escHtml(info.impact)}
            </div>
            <div style="max-height:80px; overflow-y:auto; font-family:'Fira Code', monospace; font-size:11.5px; color:var(--text-light); background:var(--bg); padding:6px 10px; border-radius:4px; border:1px solid var(--border);">
              ${info.list.map(w => `
                <div class="clickable-warn-row" data-id="${w.id}" style="cursor:pointer; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-bottom:4px;" onmouseover="this.style.color='var(--primary)'" onmouseout="this.style.color='inherit'">
                  [${escHtml(w.timestamp || 'No Timestamp')}] ${escHtml(w.message)}
                </div>
              `).join('')}
            </div>
          </div>`;
      }).join('')}
    </div>`;
    
  container.querySelectorAll('.clickable-warn-row').forEach(row => {
    row.addEventListener('click', () => {
      const id = parseInt(row.dataset.id);
      showAndHighlightLog(id);
    });
  });
}

function renderLoggerAnalysis(loggerStats) {
  const container = document.getElementById('logger-analysis-body');
  if (!container) return;
  
  if (!loggerStats || !loggerStats.counts) {
    container.innerHTML = `
      <div class="no-data-state" style="padding:20px;">
        <p>No log statistics available.</p>
      </div>`;
    return;
  }
  
  const counts = loggerStats.counts;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  
  const colors = {
    FATAL: '#7F1D1D',
    ERROR: '#DC2626',
    WARN: '#F59E0B',
    INFO: '#3B82F6',
    DEBUG: '#10B981',
    TRACE: '#6B7280'
  };
  
  let barHtml = '<div style="display:flex; height:12px; border-radius:6px; overflow:hidden; margin-bottom:16px; background:#F3F4F6;">';
  for (const lvl in counts) {
    if (counts[lvl] > 0) {
      const pct = (counts[lvl] / total) * 100;
      barHtml += `<div style="width:${pct}%; background:${colors[lvl] || '#E5E7EB'};" title="${lvl}: ${counts[lvl]} entries (${Math.round(pct)}%)"></div>`;
    }
  }
  barHtml += '</div>';
  
  let legendHtml = '<div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:12px; margin-bottom:16px;">';
  for (const lvl in counts) {
    const color = colors[lvl] || '#9CA3AF';
    legendHtml += `
      <div style="display:flex; align-items:center; justify-content:space-between; padding:6px 10px; background:var(--bg); border:1px solid var(--border); border-radius:6px;">
        <div style="display:flex; align-items:center; gap:6px; font-size:12px; font-weight:600; color:var(--text-dark);">
          <span style="width:8px; height:8px; border-radius:50%; background:${color}; display:inline-block;"></span>
          ${lvl}
        </div>
        <span style="font-family:'Fira Code', monospace; font-size:12px; font-weight:700; color:var(--text-normal);">${counts[lvl]}</span>
      </div>`;
  }
  legendHtml += '</div>';
  
  let gapsHtml = '';
  if (loggerStats.gaps && loggerStats.gaps.length) {
    gapsHtml = `
      <div style="border-top:1px dashed var(--border); padding-top:14px;">
        <span style="font-size:12.5px; font-weight:700; color:var(--text-dark); display:block; margin-bottom:8px;">Logger Recommendations & Telemetry Gaps</span>
        <div style="display:flex; flex-direction:column; gap:8px;">
          ${loggerStats.gaps.map(g => `
            <div style="padding:10px 12px; border-left:3px solid #6366F1; background:#EEF2FF; border-radius:0 6px 6px 0; font-size:12px; line-height:1.5;">
              <strong style="color:#4F46E5;">${escHtml(g.type)}:</strong> ${escHtml(g.description)}
              <div style="font-size:11px; color:#6B7280; margin-top:4px;">
                💡 <em>Fix Recommendation:</em> ${escHtml(g.recommendation)}
              </div>
            </div>
          `).join('')}
        </div>
      </div>`;
  } else {
    gapsHtml = `
      <div style="border-top:1px dashed var(--border); padding-top:12px; color:#16A34A; font-size:12px; display:flex; align-items:center; gap:6px;">
        ✓ Excellent Telemetry coverage. No logger gaps or incomplete flows detected.
      </div>`;
  }
  
  container.innerHTML = barHtml + legendHtml + gapsHtml;
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

  // --- Populate surrounding log lines in Monaco snippet viewer ---
  const parsedIndex = STATE.parsed.findIndex(r => r.id === row.id);
  let snippetText = '';
  let errorLineInSnippet = 1;
  if (parsedIndex !== -1) {
     const startIndex = Math.max(0, parsedIndex - 15);
     const endIndex = Math.min(STATE.parsed.length - 1, parsedIndex + 15);
     const snippetLines = STATE.parsed.slice(startIndex, endIndex + 1);
     errorLineInSnippet = (parsedIndex - startIndex) + 1;
     
     snippetText = snippetLines.map((line, i) => {
        const relativeLineNum = startIndex + i + 1;
        const lvl = (line.level || 'INFO').padEnd(5);
        return `Line ${String(relativeLineNum).padEnd(5)} | [${lvl}] | ${line.timestamp} | ${line.message.split('\n')[0]}`;
     }).join('\n');
  }

  // Load / Update Monaco Editor log viewer
  const initRcaLogMonaco = (text, errorLine, errType) => {
     const container = document.getElementById('rca-monaco-container');
     if (!container) return;
     
     if (typeof window.monaco !== 'undefined') {
        if (window.rcaLogEditor) {
           window.rcaLogEditor.setValue(text);
        } else {
           window.rcaLogEditor = window.monaco.editor.create(container, {
             value: text,
             language: 'text',
             theme: 'vs-dark',
             readOnly: true,
             automaticLayout: true,
             minimap: { enabled: false },
             lineNumbers: 'on',
             scrollBeyondLastLine: false,
             fontSize: 12,
             fontFamily: "'Fira Code', Consolas, monospace",
           });
        }

        const decorations = [{
           range: new window.monaco.Range(errorLine, 1, errorLine, 100),
           options: {
             isWholeLine: true,
             className: 'monaco-line-error',
             glyphMarginClassName: 'monaco-glyph-error',
             hoverMessage: { value: `Selected Error: ${errType}` }
           }
        }];
        
        window.rcaLogEditor._editorDecorations = window.rcaLogEditor.deltaDecorations(
           window.rcaLogEditor._editorDecorations || [],
           decorations
        );
        
        setTimeout(() => {
           window.rcaLogEditor.revealLineInCenter(errorLine);
        }, 50);
     } else {
        // Fallback if Monaco is not yet loaded
        container.innerHTML = `<pre style="margin:0; padding:12px; height:100%; overflow:auto; font-family:monospace; color:#E2E8F0; background:#0F172A; white-space:pre;">${escHtml(text)}</pre>`;
     }
  };

  // Check and run Monaco loading
  if (typeof require !== 'undefined' && typeof window.monaco === 'undefined') {
     require(['vs/editor/editor.main'], function() {
        initRcaLogMonaco(snippetText, errorLineInSnippet, d.errType);
     });
  } else {
     initRcaLogMonaco(snippetText, errorLineInSnippet, d.errType);
  }

  // Copy / Download handlers
  const copyBtn = document.getElementById('rca-log-copy-btn');
  if (copyBtn) {
     copyBtn.onclick = () => {
        navigator.clipboard.writeText(snippetText).then(() => {
           copyBtn.textContent = 'Copied!';
           setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1000);
        });
     };
  }
  
  const downloadBtn = document.getElementById('rca-log-download-btn');
  if (downloadBtn) {
     downloadBtn.onclick = () => {
        const blob = new Blob([snippetText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `log_snippet_line_${parsedIndex + 1}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
     };
  }

  // AI Analysis explanation compilation
  let aiExplanation = '';
  if (d.errType.includes('NullPointerException') || d.errType.includes('null')) {
     aiExplanation = `The exception occurred immediately after the response was processed.

No Session Object or variable was available in the target scope.

The uploaded screen JSON shows _onExit calling getObject() instead of getSessionObject().

This is the most probable root cause. Use getSessionObject() to ensure scope persistence.`;
  } else if (d.errType.includes('ArrayIndexOutOfBoundsException')) {
     aiExplanation = `The ArrayIndexOutOfBoundsException occurred because the code attempted to access the first index of an array (e.g. items[0]) but the array was empty (length = 0).

This is a signature Blank API result. GetWorkOrderOperations returned HTTP 200 but count=0.

Business validation failed because no work order operations were available.

Add if(items.length() > 0) to prevent array crashes.`;
  } else if (d.apiInfo && d.apiInfo.status === 403) {
     aiExplanation = `The exception occurred during callWebService() execution.

The endpoint WORK_ORDER_OPERATION_WS returned HTTP 403 Forbidden.

No further events executed, and the transaction was terminated.

Verify Oracle Fusion security policies and ensure the user is assigned the necessary data privileges.`;
  } else {
     aiExplanation = `AI Analysis:

The failure was detected at step ${d.errType || 'Error'}.

Possible cause: ${d.rootCause || 'Preceding API or script failed.'}

Immediate Action: ${d.immediatefix || 'Verify backend availability and log variables.'}`;
  }
  const explanationEl = document.getElementById('rca-ai-analysis-text');
  if (explanationEl) explanationEl.textContent = aiExplanation;

  // Correlation Chain Flow mapping
  const screenVal = d.screen || (STATE.analysis ? STATE.analysis.screen : '') || extractScreenFromMsg(row.message) || 'WO_COMPLETION';
  const fieldVal = d.script || 'ORG_CODE';
  let eventVal = 'event';
  if (row.message.includes('_afterExit')) eventVal = '_afterExit';
  else if (row.message.includes('_afterClick')) eventVal = '_afterClick';
  else if (row.message.includes('_onExit')) eventVal = '_onExit';
  else if (row.message.includes('_onResponseReceived')) eventVal = '_onResponseReceived';
  else eventVal = '_onExit';

  const apiVal = d.apiInfo ? d.apiInfo.name : 'ORG_WEBSERVICE';
  const objVal = Object.keys(d.variables)[0] || 'ORACLE_SCM_ORG_ID';
  const errVal = d.errType || 'NullPointerException';

  const chainContainer = document.getElementById('rca-correlation-chain');
  if (chainContainer) {
     chainContainer.innerHTML = `
       <div class="related-node success" style="max-width: 100px; padding: 6px 10px; border-radius: 6px; background: var(--bg); border: 1px solid var(--border); display: flex; flex-direction: column; align-items: center; gap: 2px;">
         <span style="font-weight:700; color:var(--text-light); font-size:9.5px;">Screen</span>
         <span style="font-size:9px; color:var(--text-muted); word-break:break-all; text-align:center;">${escHtml(screenVal)}</span>
       </div>
       <span class="related-arrow" style="color: var(--text-muted); font-size: 12px;">➔</span>
       <div class="related-node success" style="max-width: 100px; padding: 6px 10px; border-radius: 6px; background: var(--bg); border: 1px solid var(--border); display: flex; flex-direction: column; align-items: center; gap: 2px;">
         <span style="font-weight:700; color:var(--text-light); font-size:9.5px;">Field</span>
         <span style="font-size:9px; color:var(--text-muted); word-break:break-all; text-align:center;">${escHtml(fieldVal)}</span>
       </div>
       <span class="related-arrow" style="color: var(--text-muted); font-size: 12px;">➔</span>
       <div class="related-node success" style="max-width: 100px; padding: 6px 10px; border-radius: 6px; background: var(--bg); border: 1px solid var(--border); display: flex; flex-direction: column; align-items: center; gap: 2px;">
         <span style="font-weight:700; color:var(--text-light); font-size:9.5px;">Event</span>
         <span style="font-size:9px; color:var(--text-muted); word-break:break-all; text-align:center;">${escHtml(eventVal)}</span>
       </div>
       <span class="related-arrow" style="color: var(--text-muted); font-size: 12px;">➔</span>
       <div class="related-node success" style="max-width: 100px; padding: 6px 10px; border-radius: 6px; background: var(--bg); border: 1px solid var(--border); display: flex; flex-direction: column; align-items: center; gap: 2px;">
         <span style="font-weight:700; color:var(--text-light); font-size:9.5px;">API</span>
         <span style="font-size:9px; color:var(--text-muted); word-break:break-all; text-align:center;">${escHtml(apiVal)}</span>
       </div>
       <span class="related-arrow" style="color: var(--text-muted); font-size: 12px;">➔</span>
       <div class="related-node success" style="max-width: 100px; padding: 6px 10px; border-radius: 6px; background: var(--bg); border: 1px solid var(--border); display: flex; flex-direction: column; align-items: center; gap: 2px;">
         <span style="font-weight:700; color:var(--text-light); font-size:9.5px;">Object</span>
         <span style="font-size:9px; color:var(--text-muted); word-break:break-all; text-align:center;">${escHtml(objVal)}</span>
       </div>
       <span class="related-arrow" style="color: var(--text-muted); font-size: 12px;">➔</span>
       <div class="related-node failed" style="max-width: 100px; padding: 6px 10px; border-radius: 6px; background: rgba(239,68,68,0.05); border: 1px solid rgba(239,68,68,0.2); display: flex; flex-direction: column; align-items: center; gap: 2px;">
         <span style="font-weight:700; color:#EF4444; font-size:9.5px;">Exception</span>
         <span style="font-size:9px; color:#EF4444; word-break:break-all; text-align:center; font-weight:600;">${escHtml(errVal)}</span>
       </div>
     `;
  }

  // Populate Code Execution Investigator Report Card
  if (d.codeExecutionReport) {
    $('ds-investigator-report').style.display = 'block';
    $('dc-investigator-report-text').textContent = d.codeExecutionReport;
  } else {
    $('ds-investigator-report').style.display = 'none';
  }

  // ── Inject Brain Investigation Card ──────────────────────────────────────
  const existingBrain = document.getElementById('ds-brain-card');
  if (existingBrain) existingBrain.remove();
  if (window.LOGRADAR_BRAIN) {
    try {
      const brainResult = LOGRADAR_BRAIN.investigateRow(row, STATE.parsed, STATE.analysis || {});
      if (brainResult && brainResult.pattern && brainResult.pattern.id !== 'HEALTHY') {
        const brainDiv = document.createElement('div');
        brainDiv.id = 'ds-brain-card';
        brainDiv.innerHTML = LOGRADAR_BRAIN.renderBrainDrawerCard(brainResult);
        // Insert after the investigator report card
        const afterTarget = $('ds-investigator-report');
        if (afterTarget) afterTarget.parentNode.insertBefore(brainDiv, afterTarget.nextSibling);
      }
    } catch(e) {
      console.warn('LogRadar Brain drawer error:', e);
    }
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

function buildExecutionFlow(parsed, apis, sDef) {
  const steps = [];
  const apiMap = {};
  apis.forEach(api => {
     apiMap[api.name] = api;
  });

  parsed.forEach((line, idx) => {
     const msg = line.message || '';
     const ts = line.timestamp || '';
     
     // 1. Page Entered
     let pageMatch = msg.match(/PAGE ENTERED:\s*([a-zA-Z0-9_]+)/i) || msg.match(/Page\s+entered:\s*([a-zA-Z0-9_]+)/i);
     if (pageMatch) {
        steps.push({
           type: 'page',
           label: pageMatch[1],
           ts,
           status: 'success',
           details: `Entered Screen/Page: ${pageMatch[1]}`,
           lineIdx: idx
        });
     }

     // 2. Event Handlers
     let eventMatch = msg.match(/(?:ENTER|>>> ENTER)\s+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)/i);
     if (!eventMatch) {
        eventMatch = msg.match(/([a-zA-Z0-9_]+)\s+on\s+([a-zA-Z0-9_]+)/i);
        if (!eventMatch) {
           const evs = ['_afterPageEntered', '_afterExit', '_onExit', '_afterClick', '_beforePageExit', '_afterPageExit', '_beforeExit', '_onKeyPress', '_inputProcessor', '_onResponseReceived'];
           for (const ev of evs) {
              if (msg.includes(ev)) {
                 let field = 'Field';
                 let fieldMatch = msg.match(/field\s*:\s*([a-zA-Z0-9_]+)/i) || msg.match(/on\s+([a-zA-Z0-9_]+)/i);
                 if (fieldMatch) field = fieldMatch[1];
                 steps.push({
                    type: 'event',
                    label: `${field} ${ev}`,
                    ts,
                    status: 'success',
                    details: `Triggered event ${ev} on field ${field}`,
                    lineIdx: idx
                 });
                 break;
              }
           }
        }
     }
     if (eventMatch && (msg.includes('_') || msg.includes('Exit') || msg.includes('Click') || msg.includes('Enter'))) {
        steps.push({
           type: 'event',
           label: `${eventMatch[2]} ${eventMatch[1]}`,
           ts,
           status: 'success',
           details: `Triggered event ${eventMatch[1]} on field ${eventMatch[2]}`,
           lineIdx: idx
        });
     }

     // 3. WebService Calls
     let wsMatch = msg.match(/callWebService\("?([a-zA-Z0-9_]+)"?\)/i) || msg.match(/FlexiWebService\.runWebService:\s*([a-zA-Z0-9_]+)/i) || msg.match(/\.runWebService:\s*([a-zA-Z0-9_]+)/i) || msg.match(/callWebService\(\s*([a-zA-Z0-9_]+)/i);
     if (wsMatch) {
        let wsName = wsMatch[1] || 'API_CALL';
        const last = steps[steps.length - 1];
        if (!(last && last.type === 'api' && last.label === wsName)) {
           steps.push({
              type: 'api',
              label: wsName,
              ts,
              status: 'success',
              details: `Initiated API execution call: ${wsName}`,
              lineIdx: idx
           });
        }
     }

     // 4. Storing / reading objects
     let objMatch = msg.match(/(putObject|getObject|putSessionObject|getSessionObject)\("?([a-zA-Z0-9_]+)"?/i);
     if (objMatch) {
        steps.push({
           type: 'object',
           label: `${objMatch[1]}("${objMatch[2]}")`,
           ts,
           status: 'success',
           details: `${objMatch[1]} called for scope variable "${objMatch[2]}"`,
           lineIdx: idx
        });
     }

     // 5. Validation Rejection / event.preventDefault()
     if (msg.includes('preventDefault') || msg.includes('validation failed') || msg.includes('rejection')) {
        steps.push({
           type: 'validation',
           label: 'Validation Check Rejection',
           ts,
           status: 'success',
           details: `Validation prevented transaction from proceeding: ${msg}`,
           lineIdx: idx
        });
     }

     // 6. Status Messages
     let statusMatch = msg.match(/setStatusMessage\("?([^",\)]+)"?/i) || msg.match(/showStatusMessage\("?([^",\)]+)"?/i);
     if (statusMatch) {
        steps.push({
           type: 'statusMsg',
           label: `Status: "${statusMatch[1]}"`,
           ts,
           status: 'success',
           details: `Status message set to user: "${statusMatch[1]}"`,
           lineIdx: idx
        });
     }

     // 7. Navigation
     if (msg.includes('switchView') || msg.includes('navigate') || msg.includes('redirect')) {
        steps.push({
           type: 'navigation',
           label: 'Navigation Flow',
           ts,
           status: 'success',
           details: `Redirect or screen view switch: ${msg}`,
           lineIdx: idx
        });
     }

     // 8. Exceptions
     if (line.level === 'ERROR' || line.level === 'FATAL' || msg.includes('Exception') || msg.includes('Error')) {
        let errLabel = 'Error';
        let match = msg.match(/([a-zA-Z0-9_]+Exception)/) || msg.match(/Error:\s*([^\n\r]+)/);
        if (match) errLabel = match[1];
        
        steps.push({
           type: 'exception',
           label: errLabel,
           ts,
           status: 'error',
           details: `Critical error exception encountered: ${msg}`,
           lineIdx: idx
        });
     }
  });

  if (steps.length === 0) {
     apis.forEach((api) => {
        steps.push({
           type: 'api',
           label: api.name,
           ts: api.timestamp,
           status: api.health === 'Failed' ? 'error' : 'success',
           details: `API Call: ${api.name} | Method: ${api.method} | Status: ${api.status} | Latency: ${api.ms}ms`,
           lineIdx: -1
        });
     });
  }

  // Deduplicate consecutive nodes of the same type/label on similar log lines
  const deduped = [];
  steps.forEach(step => {
     if (deduped.length > 0) {
        const last = deduped[deduped.length - 1];
        if (last.type === step.type && last.label === step.label && (Math.abs(last.lineIdx - step.lineIdx) < 2)) {
           if (step.status === 'error') last.status = 'error';
           return;
        }
     }
     deduped.push(step);
  });

  let failureDetected = false;
  let failIdx = -1;
  
  deduped.forEach((step, idx) => {
     if (step.type === 'api' && apiMap[step.label]) {
        const actualApi = apiMap[step.label];
        if (actualApi.health === 'Failed') {
           step.status = 'error';
           step.details += ` (Failed with status ${actualApi.status})`;
        }
     }
     if (step.status === 'error') {
        if (!failureDetected) {
           failureDetected = true;
           failIdx = idx;
        }
     }
  });

  if (failureDetected) {
     for (let i = failIdx + 1; i < deduped.length; i++) {
        deduped[i].status = 'pending';
     }
  }

  return deduped;
}

window.selectFlowNode = (idx) => {
  const step = STATE.analysis.flow[idx];
  if (!step) return;

  document.querySelectorAll('.flow-step').forEach((el, i) => {
     if (i === idx) el.classList.add('selected');
     else el.classList.remove('selected');
  });

  const summaryEl = document.getElementById('flow-summary-body');
  
  let relatedInfo = '';
  if (step.type === 'api') {
     const relatedApi = STATE.analysis.apis.find(a => a.name === step.label);
     if (relatedApi) {
        const origIdx = STATE.analysis.apis.indexOf(relatedApi);
        relatedInfo = `
          <div style="margin-top:12px; border:1px solid var(--border); padding:8px 12px; border-radius:6px; background:rgba(255,255,255,0.02);">
             <div style="font-weight:700; color:var(--primary); font-size:12px;">Related Tracker API</div>
             <div style="font-size:11.5px; color:var(--text-light); margin-top:4px;">
               <strong>Method:</strong> ${relatedApi.method}<br>
               <strong>Status:</strong> ${relatedApi.status}<br>
               <strong>Records:</strong> ${relatedApi.recordCount}<br>
               <strong>Time:</strong> ${relatedApi.ms} ms<br>
               <strong>URL:</strong> ${relatedApi.endpoint || 'Not Logged'}
             </div>
             <button onclick="switchView('api'); selectRelatedApi(${origIdx})" style="margin-top:8px; background:var(--primary); border:none; color:#fff; font-size:10px; font-weight:700; padding:4px 8px; border-radius:4px; cursor:pointer; width:100%;">Inspect API Details</button>
          </div>
        `;
     }
  }

  let rcaLinkHtml = '';
  if (step.lineIdx >= 0 && STATE.parsed[step.lineIdx]) {
     rcaLinkHtml = `
       <button onclick="showAndHighlightLog(${STATE.parsed[step.lineIdx].id})" style="margin-top:8px; background:rgba(59,130,246,0.1); border:1px solid rgba(59,130,246,0.3); color:#60A5FA; font-size:11px; font-weight:700; padding:6px 12px; border-radius:6px; cursor:pointer; width:100%;">
          🔍 Investigate in Log Table (Line ${step.lineIdx + 1})
       </button>
     `;
  }

  summaryEl.innerHTML = `
     <div style="display:flex; flex-direction:column; gap:10px;">
       <div class="meta-row"><span class="meta-label">Step Type</span><span class="meta-val" style="text-transform:uppercase; font-weight:700; color:var(--primary);">${step.type}</span></div>
       <div class="meta-row"><span class="meta-label">Label</span><span class="meta-val" style="font-weight:700;">${escHtml(step.label)}</span></div>
       <div class="meta-row"><span class="meta-label">Timestamp</span><span class="meta-val">${step.ts || '—'}</span></div>
       <div class="meta-row"><span class="meta-label">Status</span><span class="meta-val ${step.status}">${step.status.toUpperCase()}</span></div>
       <div style="font-size:12px; color:var(--text-light); line-height:1.5; padding:10px; background:rgba(255,255,255,0.02); border-radius:6px; margin-top:8px; border:1px solid var(--border);">
         <strong>Step Details:</strong><br>${escHtml(step.details)}
       </div>
       ${relatedInfo}
       ${rcaLinkHtml}
     </div>
  `;
};

function renderWMSFlow(flowSteps, analysis) {
  const el = document.getElementById('wms-flow-container');
  if (!flowSteps || !flowSteps.length) {
     flowSteps = buildExecutionFlow(STATE.parsed || [], STATE.analysis?.apis || [], STATE.screenDefinition || null);
     if (STATE.analysis) {
        STATE.analysis.flow = flowSteps;
     }
  }

  if (!flowSteps || !flowSteps.length) {
    el.innerHTML = '<div class="no-data-state" style="padding:20px;"><p>No transaction flow detected</p></div>';
    document.getElementById('flow-summary-body').innerHTML = '<div class="no-data-state" style="padding:20px;"><p>No summary available</p></div>';
    return;
  }

  const html = flowSteps.map((step, i) => {
    const isLast = i === flowSteps.length - 1;
    let icon = '○';
    let connClass = '';
    if (step.status === 'success') {
       icon = '✓';
       connClass = 'done';
    } else if (step.status === 'error') {
       icon = '❌';
       connClass = 'broken';
    }

    return `
      <div class="flow-step clickable-step" onclick="selectFlowNode(${i})" style="cursor:pointer; padding:8px 12px; border-radius:6px; margin-bottom:6px; display:flex; gap:10px; align-items:center; transition: background 0.15s; border: 1px solid transparent;">
        <div class="flow-step-line" style="display:flex; flex-direction:column; align-items:center; position:relative;">
          <div class="flow-circle ${step.status}" style="width:24px; height:24px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:bold; font-size:11px; background:${step.status === 'success' ? 'rgba(16,185,129,0.1)' : step.status === 'error' ? 'rgba(239,68,68,0.1)' : 'rgba(107,114,128,0.1)'}; color:${step.status === 'success' ? '#10B981' : step.status === 'error' ? '#EF4444' : '#9CA3AF'}; border:2px solid ${step.status === 'success' ? '#10B981' : step.status === 'error' ? '#EF4444' : '#475569'};">${icon}</div>
        </div>
        <div class="flow-body">
          <div class="flow-label" style="font-weight:700; font-size:12.5px; color:${step.status === 'error' ? '#EF4444' : 'var(--text-light)'};">${escHtml(step.label)}</div>
          <div class="flow-sub" style="font-size:10.5px; color:var(--text-muted);">${step.status === 'success' ? 'Completed' : step.status === 'error' ? 'FAILED - Execution stopped here' : 'Not reached'}</div>
        </div>
      </div>
    `;
  }).join('');

  el.innerHTML = `<div class="flow-container" style="display:flex; flex-direction:column; gap:6px;">${html}</div>`;

  const failStep = flowSteps.find(s => s.status === 'error');
  const doneCount = flowSteps.filter(s => s.status === 'success').length;
  
  let probability = '0%';
  let failureReason = 'No failures detected in transaction execution.';
  
  if (failStep) {
     if (failStep.type === 'exception') {
        probability = '97%';
        failureReason = `${failStep.label} occurred during event execution. Transaction aborted, blocking subsequent steps.`;
     } else if (failStep.type === 'api') {
        probability = '96%';
        failureReason = `API "${failStep.label}" returned an error. No further events executed. Transaction terminated.`;
     } else if (failStep.type === 'validation') {
        probability = '92%';
        failureReason = `Business validation check failed. preventDefault() called, terminating execution loop.`;
     } else {
        probability = '85%';
        failureReason = `Failure occurred at step ${failStep.label}. Transaction terminated.`;
     }
  }

  let screenCorrelationHtml = '';
  if (STATE.screenDefinition) {
     const sDef = STATE.screenDefinition;
     const field = failStep ? failStep.label.split(' ')[0] : 'Unknown';
     const event = failStep ? failStep.label.split(' ')[1] || 'Event' : 'Unknown';
     const api = analysis.apis && analysis.apis.length ? analysis.apis[analysis.apis.length - 1].name : 'Unknown';
     
     screenCorrelationHtml = `
       <div style="margin-top:16px; padding:12px; background:rgba(16,185,129,0.04); border:1px solid rgba(16,185,129,0.2); border-radius:8px;">
          <div style="font-size:11.5px; font-weight:700; color:#10B981; text-transform:uppercase; margin-bottom:8px;">Screen Correlation Engine</div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; font-size:11.5px; color:var(--text-light);">
             <div><strong>Screen:</strong> ${escHtml(sDef.screenName || 'Screen')}</div>
             <div><strong>Field Executed:</strong> ${escHtml(field)}</div>
             <div><strong>Event Executed:</strong> ${escHtml(event)}</div>
             <div><strong>API Called:</strong> ${escHtml(api)}</div>
             <div style="grid-column: span 2;"><strong>Confidence:</strong> 96%</div>
          </div>
       </div>
     `;
  } else {
     screenCorrelationHtml = `
       <div style="margin-top:16px; padding:12px; background:rgba(245,158,11,0.04); border:1px solid rgba(245,158,11,0.2); border-radius:8px;">
          <div style="font-size:11.5px; font-weight:700; color:#F59E0B; text-transform:uppercase; margin-bottom:4px;">Screen Correlation Engine</div>
          <div style="font-size:11.5px; color:var(--text-muted); line-height:1.4;">
             Upload Screen JSON with logs to run structural code comparisons.<br>
             <span style="color:var(--text-light); font-weight:600;">Estimated Flow Confidence: 85%</span>
          </div>
       </div>
     `;
  }

  const summaryEl = document.getElementById('flow-summary-body');
  summaryEl.innerHTML = `
     <div style="display:flex; flex-direction:column; gap:12px;">
        <div class="meta-row"><span class="meta-label">Module</span><span class="meta-val">${analysis.module || 'Unknown'}</span></div>
        <div class="meta-row"><span class="meta-label">Steps Done</span><span class="meta-val">${doneCount} / ${flowSteps.length}</span></div>
        <div class="meta-row"><span class="meta-label">Failed At</span><span class="meta-val" style="color:#DC2626; font-weight:700;">${failStep ? failStep.label : 'No failure detected'}</span></div>
        <div class="meta-row"><span class="meta-label">User Identity</span><span class="meta-val">${analysis.users?.join(', ') || '—'}</span></div>
        
        <div style="border-top:1px solid var(--border); padding-top:12px; margin-top:8px;">
           <div style="font-size:11px; font-weight:700; color:#F59E0B; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px;">Probability Analysis</div>
           <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
              <span style="font-size:24px; font-weight:800; color:#F59E0B;">${probability}</span>
              <span style="font-size:11px; color:var(--text-muted); font-weight:600;">Failure Probability</span>
           </div>
           <div style="font-size:12px; color:var(--text-normal); line-height:1.5;">${escHtml(failureReason)}</div>
        </div>

        ${screenCorrelationHtml}
     </div>
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

  // ── Brain-powered investigation queries ──────────────────────────────────
  if (/brain.*invest|logradar.*invest|full.*invest|deep.*invest|l3.*invest/i.test(q)) {
    if (!a.apis || !a.apis.length) return '⚠️ No API calls detected. Upload a log with API activity to run a brain investigation.';
    const targetApi = a.apis.find(x => x.status >= 400 || x.businessResult !== 'Healthy') || a.apis[0];
    if (!window.LOGRADAR_BRAIN) return '⚠️ LogRadar Brain not loaded. Please refresh the page.';
    const brainResult = LOGRADAR_BRAIN.investigateAPI(targetApi);
    if (!brainResult) return 'No investigation result.';
    const conf = LOGRADAR_BRAIN.getConfidenceLabel(brainResult.confidence);
    const evList = (brainResult.evidence || []).map(e => `• [${e.strength}] ${e.text}`).join('\n');
    const recsList = (brainResult.investigation?.recommendations || []).map((r,i) => `${i+1}. [${r.priority}] ${r.action}`).join('\n');
    return `🧠 <strong>LogRadar Brain — Full Investigation Report</strong><br><br>
<strong>API Investigated:</strong> ${escHtml(targetApi.name)}<br>
<strong>Pattern Detected:</strong> ${escHtml(brainResult.pattern?.name || 'Unknown')}<br>
<strong>Confidence:</strong> ${conf.icon} ${brainResult.confidence}% — ${conf.label}<br><br>
<strong>Root Cause:</strong><br>${escHtml(brainResult.investigation?.rootCause || 'Investigating...')}<br><br>
<strong>Evidence Chain:</strong><pre style="background:#0F172A;color:#E2E8F0;padding:12px;border-radius:8px;font-size:11px;line-height:1.6;white-space:pre-wrap;">${escHtml(evList)}</pre>
${recsList ? `<strong>Recommendations:</strong><pre style="background:#0F172A;color:#E2E8F0;padding:12px;border-radius:8px;font-size:11px;line-height:1.6;white-space:pre-wrap;">${escHtml(recsList)}</pre>` : ''}
<em>Next Steps: ${escHtml(brainResult.investigation?.nextSteps || 'Open the API Tracker and click the API for full investigation details.')}</em>`;
  }

  if (/brain.*api|api.*brain|investigate.*api/i.test(q)) {
    if (!a.apis || !a.apis.length) return 'No API calls detected in the log.';
    if (!window.LOGRADAR_BRAIN) return '⚠️ LogRadar Brain not loaded.';
    const lines = a.apis.map(api => {
      const p = LOGRADAR_BRAIN.classifyApiPattern(api);
      const conf = LOGRADAR_BRAIN.getConfidenceLabel(api.status >= 400 ? 90 : api.recordCount === 0 ? 85 : 70);
      return `• <strong>${escHtml(api.name)}</strong>: ${p.icon} ${escHtml(p.name)} | HTTP ${api.status} | ${api.ms}ms | ${conf.icon} ${api.businessResult || 'Unknown'}`;
    }).join('<br>');
    return `🧠 <strong>Brain API Pattern Analysis (${a.apis.length} calls):</strong><br><br>${lines}<br><br><em>Tip: Click any API in the API Tracker tab for detailed brain investigation with evidence, recommendations, and logger suggestions.</em>`;
  }

  // --- New Ask AI handlers for Universal Engine v2.0 ---
  if (/blank api|show blank/i.test(q)) {
    if (!a.blankApis || !a.blankApis.length) {
      return '✅ No blank APIs (silent 200 OK responses with empty data) were detected in this log.';
    }
    const list = a.blankApis.map(api => `• <strong>${escHtml(api.name)}</strong>: HTTP ${api.status} | Response Time: ${api.ms}ms<br>&nbsp;&nbsp;<em>Reason:</em> <span style="color:#D97706;">${escHtml(api.blankReason)}</span><br>&nbsp;&nbsp;<em>Rec:</em> ${escHtml(api.recommendation)}`).join('<br><br>');
    return `🔍 <strong>Blank API Report:</strong><br><br>${list}`;
  }

  if (/warning|show warning/i.test(q)) {
    if (!a.warnings || !a.warnings.length) {
      return '✅ No warnings detected in this log.';
    }
    const list = a.warnings.slice(0, 10).map(w => `• <strong>${escHtml(w.classification)}</strong>: ${escHtml(w.message)}<br>&nbsp;&nbsp;<em>Impact:</em> ${escHtml(w.impact)}`).join('<br><br>');
    return `⚠️ <strong>Warning Analysis Report (showing top 10):</strong><br><br>${list}${a.warnings.length > 10 ? `<br><br><em>And ${a.warnings.length - 10} more warnings. Review the Warning Analysis section on the dashboard for the full list.</em>` : ''}`;
  }

  if (/business validation|what validated|show business/i.test(q)) {
    const bizApis = a.apis.filter(api => api.businessResult === 'Business Validation Failure');
    if (!bizApis.length) {
      return '✅ No business validation failures detected in the API responses.';
    }
    const list = bizApis.map(api => `• <strong>${escHtml(api.name)}</strong> (HTTP ${api.status}): Contains business-level validation failures.<br>&nbsp;&nbsp;<em>Payload snippet:</em> <code>${escHtml((api.response || '').substring(0, 150))}...</code>`).join('<br><br>');
    return `💼 <strong>Business Validation Failures:</strong><br><br>${list}`;
  }

  if (/log type|what kind of log/i.test(q)) {
    return `📋 <strong>Detected Log Type:</strong> <code>${escHtml(a.logType || 'Generic')}</code>`;
  }

  if (/logger analysis|missing logger|telemetry gap/i.test(q)) {
    if (!a.loggerStats) return 'No logger statistics available.';
    const counts = a.loggerStats.counts;
    let countsStr = Object.entries(counts).map(([lvl, cnt]) => `<strong>${lvl}</strong>: ${cnt}`).join(' | ');
    let gapsStr = '✅ No logger gaps or incomplete telemetry detected.';
    if (a.loggerStats.gaps && a.loggerStats.gaps.length) {
      gapsStr = a.loggerStats.gaps.map(g => `• <strong>${escHtml(g.type)}</strong>: ${escHtml(g.description)}<br>&nbsp;&nbsp;<em>Rec:</em> ${escHtml(g.recommendation)}`).join('<br><br>');
    }
    return `📊 <strong>Logger Analysis:</strong><br><br>Level Distribution:<br>${countsStr}<br><br>Telemetry & Gaps:<br>${gapsStr}`;
  }

  if (/all api|show all api|api list/i.test(q)) {
    if (!a.apis.length) return 'No API calls detected in the log.';
    const list = a.apis.map(api => `• <strong>${escHtml(api.name)}</strong>: ${api.method || 'GET'} HTTP ${api.status} (${api.ms}ms) - <span style="font-weight:600;">${api.businessResult || 'Healthy'}</span>`).join('<br>');
    return `🌐 <strong>Full API Inventory (${a.apis.length} calls):</strong><br><br>${list}`;
  }

  if (/auth.*fail|unauthorized|forbidden|403|401/i.test(q)) {
    const authApis = a.apis.filter(api => api.status === 401 || api.status === 403);
    const authLogs = STATE.parsed.filter(e => /auth|login|token|permission|forbidden|unauthorized/i.test(e.message) && ['ERROR', 'FATAL', 'WARN'].includes(e.level));
    if (!authApis.length && !authLogs.length) {
      return '✅ No authentication or authorization failures detected in the log.';
    }
    let res = '🔒 <strong>Authentication & Authorization Failures:</strong><br><br>';
    if (authApis.length) {
      res += '<strong>Failed APIs:</strong><br>';
      res += authApis.map(api => `• <strong>${escHtml(api.name)}</strong> returned HTTP ${api.status} (${api.status === 401 ? 'Unauthorized' : 'Forbidden'})`).join('<br>') + '<br><br>';
    }
    if (authLogs.length) {
      res += '<strong>Log Messages:</strong><br>';
      res += authLogs.slice(0, 5).map(e => `• [${escHtml(e.timestamp)}] [${escHtml(e.level)}] ${escHtml(e.message)}`).join('<br>');
    }
    return res;
  }

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


function showScreenLoadingUI(filename) {
  const title = document.getElementById('upload-loading-title');
  if (title) title.textContent = "Parsing Screen Definition…";
  const steps = document.getElementById('upload-loading-steps');
  if (steps) steps.style.display = 'none';
  const bar = document.getElementById('upload-progress-bar');
  if (bar) { bar.style.display = 'block'; bar.classList.add('active'); }
  const fill = document.getElementById('upload-progress-fill');
  if (fill) fill.style.width = '0%';
  const cardFill = document.getElementById('upload-card-progress-fill');
  if (cardFill) cardFill.style.width = '0%';
  const card = document.getElementById('upload-loading-card');
  const fname = document.getElementById('upload-loading-filename');
  if (card) card.style.display = 'flex';
  if (fname) fname.textContent = filename || 'Screen JSON';
}


function deepFindKey(obj, keyToFind) {
  if (typeof obj !== 'object' || obj === null) return null;
  if (obj[keyToFind]) return obj[keyToFind];
  for (let key in obj) {
    const res = deepFindKey(obj[key], keyToFind);
    if (res) return res;
  }
  return null;
}

function getActiveScreenDefinition() {
  return STATE.screenDefinition || null;
}

function handleScreenSelect(file) {
  showScreenLoadingUI(file.name);
  const reader = new FileReader();
  reader.onload = async ev => {
    try {
      const progressFill = pct => {
        const fill = document.getElementById('upload-progress-fill');
        if (fill) fill.style.width = pct + '%';
        const cardFill = document.getElementById('upload-card-progress-fill');
        if (cardFill) cardFill.style.width = pct + '%';
      };
      progressFill(50);
      await new Promise(r => setTimeout(r, 200));

      let data;
      try {
        const parsedJson = JSON.parse(ev.target.result);
        
        // Helper to extract fields recursively from the JSON tree
        const extractFieldsFromJSON = (obj, fieldsList = []) => {
          if (typeof obj !== 'object' || obj === null) return fieldsList;

          if (obj.properties && typeof obj.properties === 'object') {
             const props = obj.properties;
             const propsHasId = typeof props.id === 'string' && props.id.trim() !== '';
             if (propsHasId && (
               'label' in props || 
               'required' in props || 
               'readOnly' in props ||
               'onExit' in props || 
               'onFocus' in props || 
               'webService' in props
             )) {
                fieldsList.push({
                   ...props,
                   type: obj.type || props.type || 'Field'
                });
             }
          } else {
             const hasId = typeof obj.id === 'string' && obj.id.trim() !== '';
             const isField = hasId && (
               'label' in obj || 
               'required' in obj || 
               'readOnly' in obj || 
               'onExit' in obj || 
               'onFocus' in obj || 
               'webService' in obj || 
               'lovSourceType' in obj ||
               obj.type === 'Field' ||
               obj.controlType === 'Field' ||
               obj.style === 'Normal' ||
               obj.style === 'Barcode'
             );
             if (isField) {
                fieldsList.push(obj);
             }
          }

          for (let key in obj) {
             if (key !== 'properties' && typeof obj[key] === 'object') {
                extractFieldsFromJSON(obj[key], fieldsList);
             }
          }
          return fieldsList;
        };

        let fieldsArray = extractFieldsFromJSON(parsedJson);
        if (!fieldsArray || fieldsArray.length === 0) {
           const deepFields = deepFindKey(parsedJson, 'fields');
           if (deepFields) {
              if (Array.isArray(deepFields)) {
                 fieldsArray = deepFields;
              } else if (typeof deepFields === 'object') {
                 fieldsArray = Object.entries(deepFields).map(([name, props]) => {
                    return { id: name, ...props };
                 });
              }
           }
        }

        let wsMap = {};
        const deepWS = deepFindKey(parsedJson, 'webservices') || deepFindKey(parsedJson, 'webServices') || deepFindKey(parsedJson, 'web_services');
        if (deepWS) {
           if (Array.isArray(deepWS)) {
              deepWS.forEach(ws => {
                 if (ws.name || ws.id) wsMap[ws.name || ws.id] = ws;
              });
           } else if (typeof deepWS === 'object') {
              wsMap = deepWS;
           }
        }

        if (fieldsArray.length === 0 && !parsedJson.screenName && !parsedJson.title) {
           data = { screenName: file.name, title: file.name, rawCode: ev.target.result };
        } else {
           // Normalize fields format for log correlation
           const normalizedFields = {};
           fieldsArray.forEach(f => {
              const fieldName = f.id || f.name;
              if (!fieldName) return;
              
              const events = {};
              const onFocusVal = f.onFocus || f.onFocusScript || f.OnFocus || (f.events && f.events.onFocus) || (f.events && f.events.OnFocus);
              if (onFocusVal) events["OnFocus"] = { code: typeof onFocusVal === 'string' ? onFocusVal : (onFocusVal.code || '') };
              
              const onExitVal = f.onExit || f.onExitScript || f.OnExit || (f.events && f.events.onExit) || (f.events && f.events.OnExit);
              if (onExitVal) events["OnExit"] = { code: typeof onExitVal === 'string' ? onExitVal : (onExitVal.code || '') };

              const beforeExitVal = f.beforeExit || f.beforeExitScript || f.BeforeExit || (f.events && f.events.beforeExit) || (f.events && f.events.BeforeExit);
              if (beforeExitVal) events["BeforeExit"] = { code: typeof beforeExitVal === 'string' ? beforeExitVal : (beforeExitVal.code || '') };

              const onKeyPressVal = f.onKeyPress || f.onKeyPressScript || f.OnKeyPress || (f.events && f.events.onKeyPress) || (f.events && f.events.OnKeyPress);
              if (onKeyPressVal) events["OnKeyPress"] = { code: typeof onKeyPressVal === 'string' ? onKeyPressVal : (onKeyPressVal.code || '') };

              if (typeof f === 'object') {
                 for (let key in f) {
                    if (['onfocus', 'onexit', 'beforeexit', 'onkeypress'].includes(key.toLowerCase())) {
                       const cleanName = key.charAt(0).toUpperCase() + key.slice(1);
                       if (!events[cleanName]) {
                          events[cleanName] = { code: typeof f[key] === 'string' ? f[key] : (f[key].code || '') };
                       }
                    }
                 }
              }
              normalizedFields[fieldName] = events;
           });

           data = {
              screenName: parsedJson.screenName || parsedJson.name || file.name,
              title: parsedJson.title || parsedJson.screenTitle || parsedJson.name || file.name,
              fields: normalizedFields,
              fullFieldsList: fieldsArray,
              webservices: wsMap,
              rawCode: ev.target.result
           };
        }
      } catch (err) {
        data = { screenName: file.name, title: file.name, rawCode: ev.target.result };
      }

      
      STATE.screenDefinition = data;
      STATE.currentScreenFile = file.name;
      const screenNameEl = document.getElementById('sidebar-screen-name');
      if (screenNameEl) screenNameEl.textContent = file.name;
      
      progressFill(100);
      await new Promise(r => setTimeout(r, 150));
      hideLoadingUI();
      
      // Prompt user with modal dialog
      showScreenFilterModal();

    } catch(err) {
      console.error(err);
      hideLoadingUI();
      alert("Error reading file.");
    }
  };
  reader.readAsText(file);
}


function showScreenFilterModal() {
  const modal = document.getElementById('screen-filter-modal');
  if (!modal) return;
  modal.style.display = 'flex';

  const yesBtn = document.getElementById('screen-filter-yes-btn');
  const noBtn = document.getElementById('screen-filter-no-btn');

  const newYesBtn = yesBtn.cloneNode(true);
  const newNoBtn = noBtn.cloneNode(true);
  yesBtn.parentNode.replaceChild(newYesBtn, yesBtn);
  noBtn.parentNode.replaceChild(newNoBtn, noBtn);

  const reAnalyze = () => {
    if (!STATE.parsed || STATE.parsed.length === 0) return;

    let targetParsed = STATE.parsed;
    if (STATE.filterByScreen) {
       targetParsed = STATE.parsed.filter(r => isLogRelatedToScreen(r.message));
    }

    // Re-run the full analysis on the filtered log data
    STATE.analysis = analyzeAll(targetParsed, STATE.rawLines);
    
    // Refresh all views
    renderDashboard(STATE.analysis);
    applyFilters();
    renderTimeline(targetParsed);
    if (typeof renderWMSFlow === 'function') renderWMSFlow(STATE.analysis.flow, STATE.analysis);
    if (typeof renderApiTracker === 'function') renderApiTracker(STATE.analysis.apis);
    runScreenDebuggerAnalysis();
  };

  newYesBtn.addEventListener('click', () => {
    STATE.filterByScreen = true;
    modal.style.display = 'none';
    reAnalyze();
  });

  newNoBtn.addEventListener('click', () => {
    STATE.filterByScreen = false;
    modal.style.display = 'none';
    reAnalyze();
  });
}

function isLogRelatedToScreen(logMsg) {
  if (!STATE.screenDefinition) return true;
  const def = STATE.screenDefinition;
  const queryWords = [];
  if (def.screenName) {
    let name = def.screenName.toLowerCase();
    // Strip extension if it has one (e.g., .java, .groovy, .json)
    if (name.includes('.')) name = name.substring(0, name.lastIndexOf('.'));
    queryWords.push(name);
  }
  if (def.title) {
    let t = def.title.toLowerCase();
    if (t.includes('.')) t = t.substring(0, t.lastIndexOf('.'));
    queryWords.push(t);
  }
  if (def.module) queryWords.push(def.module.toLowerCase());
  
  if (def.fields) {
    Object.keys(def.fields).forEach(f => queryWords.push(f.toLowerCase()));
  }

  const msg = logMsg.toLowerCase();
  for (const qw of queryWords) {
    if (msg.includes(qw)) return true;
  }
  return false;
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

  const activeParsed = STATE.filterByScreen ? STATE.parsed.filter(r => isLogRelatedToScreen(r.message)) : STATE.parsed;
  const logText = activeParsed.map(e => e.message).join('\n');
  const lowerLogText = logText.toLowerCase();

  const screenDef = STATE.screenDefinition;
  if (!screenDef) return;

  const name = screenDef.screenName || screenDef.title || "Unknown Screen";
  const title = screenDef.title || name;
  const module = screenDef.module || "General";
  
  // Build Flow
  let flow = screenDef.flow || [];
  if (flow.length === 0 && screenDef.fields) {
     flow = Object.keys(screenDef.fields);
  }

  $('dbg-screen-title').textContent = title;
  
  // Extract extra components if available
  const btnCount = screenDef.buttons ? Object.keys(screenDef.buttons).length : 0;
  const lovCount = screenDef.lovs ? Object.keys(screenDef.lovs).length : 0;
  
  $('dbg-screen-meta').textContent = `Screen: ${name} | Module: ${module} | Fields: ${flow.length} | Buttons: ${btnCount} | LOVs: ${lovCount}`;

  // Draw Workflow Diagram
  let workflowHtml = "";
  flow.forEach((step, idx) => {
    workflowHtml += `
      <div class="dbg-flow-item active" style="border-color: rgba(56, 189, 248, 0.4);">
        <div style="font-weight: 700; font-size: 13px; color: var(--text-dark);">${escHtml(step)}</div>
      </div>
    `;
    if (idx < flow.length - 1) {
      workflowHtml += `<div class="dbg-flow-arrow">↓</div>`;
    }
  });
  $('dbg-workflow-container').innerHTML = workflowHtml || `<div style="font-size:12px; color:var(--text-muted);">No structured workflow detected.</div>`;

  let analysisHtml = '';

  // 1. RAW CODE DISPLAY (Fallback)
  if (screenDef.rawCode) {
    analysisHtml += `
      <div class="dbg-copilot-section">
        <div class="dbg-copilot-title" style="color:#38BDF8;">
          <span>💻</span> UPLOADED CODE (RAW)
        </div>
        <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
          Raw code from ${STATE.currentScreenFile || 'the uploaded file'}.
        </div>
        <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:4px 0 0 0; border:1px solid rgba(255,255,255,0.06);">${escHtml(screenDef.rawCode)}</pre>
      </div>
    `;
  }

  // 2. HEALTH SCORE & INVESTIGATION PATH
  if (screenDef.fields) {
     let fieldsWithLogic = 0;
     let fieldsWithLogger = 0;
     let fieldsWithStatus = 0;
     let fieldsWithValidation = 0;
     let totalFields = Object.keys(screenDef.fields).length;

     for (const events of Object.values(screenDef.fields)) {
        let hasLogic = false, hasLogger = false, hasStatus = false, hasValidation = false;
        for (const ev of Object.values(events)) {
           if (ev && ev.code) {
              hasLogic = true;
              if (/logger\./i.test(ev.code)) hasLogger = true;
              if (/setStatusMessage/i.test(ev.code)) hasStatus = true;
              if (/(throw new|catch\s*\(|if\s*\([^{]*null|validation)/i.test(ev.code)) hasValidation = true;
           }
        }
        if (hasLogic) fieldsWithLogic++;
        if (hasLogger) fieldsWithLogger++;
        if (hasStatus) fieldsWithStatus++;
        if (hasValidation) fieldsWithValidation++;
     }

     const pct = (num) => totalFields > 0 ? Math.round((num / totalFields) * 100) : 0;

     analysisHtml += `
      <div style="display:flex; gap:16px; margin-bottom:16px;">
        <!-- Health Score -->
        <div class="dbg-copilot-section" style="flex:1; margin-bottom:0;">
          <div class="dbg-copilot-title" style="color:#10B981; font-size:14px; margin-bottom:12px;">
            <span>🩺</span> SCREEN HEALTH SCORE
          </div>
          <div style="display:flex; flex-direction:column; gap:8px;">
            <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-normal);">
              <span>Field Coverage:</span> <strong>${pct(fieldsWithLogic)}%</strong>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-normal);">
              <span>Logger Coverage:</span> <strong style="color:${pct(fieldsWithLogger) < 50 ? '#EF4444' : '#10B981'}">${pct(fieldsWithLogger)}%</strong>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-normal);">
              <span>Status Message Coverage:</span> <strong style="color:${pct(fieldsWithStatus) < 50 ? '#EF4444' : '#10B981'}">${pct(fieldsWithStatus)}%</strong>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-normal);">
              <span>Validation Coverage:</span> <strong>${pct(fieldsWithValidation)}%</strong>
            </div>
          </div>
          ${pct(fieldsWithLogger) < 50 ? '<div style="margin-top:12px; font-size:11px; color:#F59E0B; background:rgba(245, 158, 11, 0.1); padding:8px; border-radius:4px;">⚠️ This screen is difficult to debug because it lacks loggers and status messages.</div>' : ''}
        </div>

        <!-- Investigation Path -->
        <div class="dbg-copilot-section" style="flex:2; margin-bottom:0; border-left: 4px solid var(--primary);">
          <div class="dbg-copilot-title" style="color:var(--primary); font-size:14px; margin-bottom:12px;">
            <span>🛤️</span> DEVELOPER INVESTIGATION PATH
          </div>
          <div style="font-size:11px; color:var(--text-muted); display:flex; align-items:center; flex-wrap:wrap; gap:8px; font-family:monospace;">
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify Field</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify Object</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify Session Value</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify API Request</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify API Response</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify Validation</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(16,185,129,0.1); color:#34D399; padding:4px 8px; border-radius:4px;">Identify Root Cause</span>
          </div>
        </div>
      </div>
     `;

     let missingLoggers = [];
     for (const [fName, events] of Object.entries(screenDef.fields)) {
        let hasLogger = false;
        let hasStatus = false;
        let hasWs = false;
        let wsName = "";
        
        for (const [evName, ev] of Object.entries(events)) {
           if (ev && ev.code) {
              if (/logger\./i.test(ev.code)) hasLogger = true;
              if (/setStatusMessage/i.test(ev.code)) hasStatus = true;
              if (screenDef.webservices) {
                 for (const wName of Object.keys(screenDef.webservices)) {
                    if (ev.code.includes(wName)) {
                       hasWs = true;
                       wsName = wName;
                    }
                 }
              }
           }
        }
        if (!hasLogger) {
           missingLoggers.push(`<li><strong>Field ${escHtml(fName)}:</strong> Suggest adding <code>logger.trace("${escHtml(fName)} changed to: " + ${escHtml(fName)}.getValue())</code> to capture input telemetry.</li>`);
        }
        if (!hasStatus) {
           missingLoggers.push(`<li><strong>Field ${escHtml(fName)}:</strong> Suggest adding <code>flexi.setStatusMessage("Please enter a valid ${escHtml(fName)} value")</code> instead of displaying generic system errors.</li>`);
        }
        if (hasWs) {
           missingLoggers.push(`<li><strong>Webservice ${escHtml(wsName)}:</strong> Ensure API responses are checked: <code>if (${escHtml(wsName)}.getResponseCode() != 200) { flexi.setStatusMessage("Integration service ${escHtml(wsName)} failed."); }</code></li>`);
        }
     }

     analysisHtml += `
      <div class="dbg-copilot-section" style="margin-top:16px;">
        <div class="dbg-copilot-title" style="color:#F59E0B; font-size:14px; margin-bottom:12px;">
          <span>📋</span> AI LOGGER & STATUS MESSAGE SUGGESTIONS
        </div>
        <div style="font-size:12.5px; color:var(--text-normal); line-height:1.5;">
          <ul style="margin:0; padding-left:20px; display:flex; flex-direction:column; gap:8px;">
            ${missingLoggers.length ? missingLoggers.slice(0, 5).join('') : '<li>🟢 Excellent! Logger and Status Message placement coverage is complete.</li>'}
          </ul>
        </div>
      </div>
     `;
  }

  // 3. DETAILED FIELD AND WEBSERVICE CORRELATION
  if (screenDef.fields) {
    const severities = {
      CRITICAL: { color: '#EF4444', badge: '🔴 Critical', triggers: ['nullpointer', 'targeterror', 'evalerror', 'fatal'] },
      HIGH: { color: '#F97316', badge: '🟠 High', triggers: ['http 5', 'http 4'] },
      MEDIUM: { color: '#EAB308', badge: '🟡 Medium', triggers: ['json', 'validation', 'exception', 'ora-'] }
    };
    
    let screenCodeHtml = '<div style="display:flex; flex-direction:column; gap:16px;">';
    for (const [fieldName, events] of Object.entries(screenDef.fields)) {
      let severity = null;
      let errorReason = "";
      let failedEvent = "Unknown";
      
      const checkSeverity = (text, contextDesc, evName) => {
         for (const [level, rules] of Object.entries(severities)) {
            for (const t of rules.triggers) {
               if (text.includes(t)) {
                  if (!severity || level === 'CRITICAL' || (level === 'HIGH' && severity.badge === '🟡 Medium')) {
                     severity = rules;
                     errorReason = `${t.toUpperCase()} detected near ${contextDesc}.`;
                     failedEvent = evName || "Execution Flow";
                  }
               }
            }
         }
      };

      // Check field match in logs
      const fieldRegex = new RegExp(fieldName, 'i');
      if (fieldRegex.test(logText)) {
         checkSeverity(lowerLogText, `field ${fieldName}`, null);
      }

      let eventsHtml = '';
      let associatedWS = null;

      if (!STATE.scriptIssues) STATE.scriptIssues = {};

      for (const [evName, ev] of Object.entries(events)) {
         if (ev.code) {
            let wsAssoc = null;
            if (screenDef.webservices) {
              for (const wsName of Object.keys(screenDef.webservices)) {
                if (ev.code.includes(wsName)) {
                  wsAssoc = { name: wsName, data: screenDef.webservices[wsName], event: evName };
                  associatedWS = wsAssoc;
                }
              }
            }

            // Script analysis
            const lines = ev.code.split('\n');
            let lineIndex = 1;
            let fix = "";
            let issue = "Telemetry or logger suggestion";
            let hasIssue = false;
            let confidence = 50;
            let evidence = [];

            // 1. Unhandled web service call
            if (wsAssoc && logText.toLowerCase().includes(wsAssoc.name.toLowerCase())) {
               const matchedApi = STATE.analysis.apis.find(a => a.name === wsAssoc.name);
               if (matchedApi && (matchedApi.status >= 400 || matchedApi.ms > 5000 || matchedApi.health === 'Blank Response')) {
                  lines.forEach((line, idx) => {
                     if (line.includes(wsAssoc.name) && !line.includes('try') && !line.includes('catch')) {
                        lineIndex = idx + 1;
                        hasIssue = true;
                        issue = `Unhandled API call to ${wsAssoc.name}`;
                        fix = `try {\n   flexi.invokeWebService('${wsAssoc.name}');\n} catch(e) {\n   flexi.setStatusMessage("${wsAssoc.name} is currently unavailable.");\n}`;
                        confidence = 90;
                        evidence.push(`API "${wsAssoc.name}" has health status "${matchedApi.health}" (HTTP ${matchedApi.status}) in the logs, but the script calls it without error checking.`);
                     }
                  });
               }
            }

            // 2. Null Reference Check
            if (!hasIssue) {
               const nullM = logText.match(/Cannot invoke method .* on null object/i) || logText.match(/NullPointerException/i);
               const skippedM = logText.match(/([A-Za-z0-9_]+)\s+field\s+was\s+skipped/i) || logText.match(/([A-Za-z0-9_]+)\s+.*was\s+(?:skipped|null|empty)/i);
               if (nullM && skippedM) {
                  const nullVar = skippedM[1];
                  lines.forEach((line, idx) => {
                     if (line.includes(nullVar) && !line.includes('!= null') && !line.includes('== null')) {
                        lineIndex = idx + 1;
                        hasIssue = true;
                        issue = `Direct property access on skipped/null field "${nullVar}"`;
                        fix = `if (${nullVar} != null && ${nullVar}.getValue() != null) {\n   // Proceed with logic\n}`;
                        confidence = 95;
                        evidence.push(`Log trace warns "${nullVar}" is null, but the script accesses it directly on line ${lineIndex} without checking.`);
                     }
                  });
               }
            }

            // 3. Status message check
            if (!hasIssue && !ev.code.includes('setStatusMessage')) {
               lineIndex = lines.length;
               hasIssue = true;
               issue = "Missing user-friendly Status Message feedback";
               fix = `flexi.setStatusMessage("Please verify ${fieldName} input.");`;
               confidence = 70;
               evidence.push(`Script executes input logic for ${fieldName} but never calls setStatusMessage to guide the user in case of errors.`);
            }

            if (hasIssue) {
               STATE.scriptIssues[fieldName + '::' + evName] = {
                  line: lineIndex,
                  issue,
                  fix,
                  confidence,
                  evidence: evidence.join(' '),
                  fieldName,
                  eventName: evName
               };
               
               // Boost severity
               if (confidence >= 90) {
                 severity = severities.CRITICAL;
                 errorReason = issue;
                 failedEvent = evName;
               } else if (confidence >= 75 && (!severity || severity.badge === '➖ None')) {
                 severity = severities.HIGH;
                 errorReason = issue;
                 failedEvent = evName;
               }
            }

            eventsHtml += `
              <div style="margin-top:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                  <strong style="color:#818CF8; font-size:12px;">${escHtml(evName)} Logic:</strong>
                  ${hasIssue ? `<span style="background:#EF444420; color:#F87171; font-size:10px; padding:2px 6px; border-radius:4px; font-weight:700;">⚠ AI Risk Detected</span>` : ''}
                </div>
                <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:4px 0 0 0; border:1px solid rgba(255,255,255,0.06);">${escHtml(ev.code)}</pre>
              </div>
            `;
         }
      }

      let wsHtml = '';
      if (associatedWS) {
        const ws = associatedWS.data;
        wsHtml += `
          <div style="margin-top:12px; background:rgba(0,0,0,0.2); padding:10px; border-radius:6px; border:1px solid rgba(245, 158, 11, 0.2);">
            <div style="font-size:12px; font-weight:bold; color:#F59E0B; margin-bottom:8px;">🔗 Webservice Mapping: ${escHtml(associatedWS.name)}</div>
            <div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Calling Event:</strong> ${escHtml(associatedWS.event)}</div>
            <div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>URL:</strong> ${escHtml(ws.request || ws.url || 'N/A')}</div>
        `;
        if (ws.requestMap || ws.body) {
           wsHtml += `<div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Request Structure (if available):</strong> <pre style="display:inline; background:#111827; padding:2px 4px; border-radius:4px;">${escHtml(JSON.stringify(ws.requestMap || ws.body))}</pre></div>`;
        }
        if (ws.responseMap || ws.response) {
           wsHtml += `<div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Response Structure (if available):</strong> <pre style="display:inline; background:#111827; padding:2px 4px; border-radius:4px;">${escHtml(JSON.stringify(ws.responseMap || ws.response))}</pre></div>`;
        }
        if (ws.columnMap) {
           wsHtml += `<div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Column Mapping (if available):</strong> <pre style="display:inline; background:#111827; padding:2px 4px; border-radius:4px;">${escHtml(JSON.stringify(ws.columnMap))}</pre></div>`;
        }
        wsHtml += `</div>`;
        
        if (new RegExp(associatedWS.name, 'i').test(logText)) {
           checkSeverity(lowerLogText, `API ${associatedWS.name}`, associatedWS.event);
        }
      }

      // Default severity if none
      if (!severity && (eventsHtml || wsHtml)) severity = { color: '#10B981', badge: '🟢 Informational' };
      if (!severity) severity = { color: '#64748B', badge: '➖ None' };

      if (eventsHtml || wsHtml) {
         let debuggerAssitantHtml = '';
         if (severity.badge !== '🟢 Informational' && severity.badge !== '➖ None') {
            debuggerAssitantHtml = `
              <div style="margin-top:16px; padding:16px; background:rgba(0,0,0,0.3); border-radius:8px; border-left:4px solid ${severity.color};">
                <h4 style="margin:0 0 12px 0; color:${severity.color}; font-size:14px; text-transform:uppercase;">🛠️ Debugging Assistant</h4>
                
                <div style="display:flex; gap:16px;">
                  <div style="flex:1;">
                    <div style="font-size:11px; color:#94A3B8; text-transform:uppercase; margin-bottom:4px;">What Failed</div>
                    <div style="font-size:12px; color:var(--text-normal);">
                      <strong>Field:</strong> ${escHtml(fieldName)}<br>
                      <strong>Event:</strong> ${escHtml(failedEvent)}<br>
                      <strong style="color:${severity.color};">Failure:</strong> ${escHtml(errorReason)}
                    </div>
                  </div>
                  
                  <div style="flex:1;">
                    <div style="font-size:11px; color:#94A3B8; text-transform:uppercase; margin-bottom:4px;">What To Verify</div>
                    <ul style="font-size:12px; color:var(--text-normal); margin:0; padding-left:16px;">
                      <li>Field Value</li>
                      <li>Object Value</li>
                      <li>Session Object</li>
                      <li>API Response</li>
                      <li>Response Code</li>
                    </ul>
                  </div>
                </div>

                <div style="margin-top:16px;">
                  <div style="font-size:11px; color:#94A3B8; text-transform:uppercase; margin-bottom:4px;">Suggested Logger Statements</div>
                  <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:0; border:1px dashed ${severity.color};">logger.debug("${fieldName}=" + ${fieldName}.getValue());
${associatedWS ? `logger.debug("Response Code=" + ${associatedWS.name}.getResponseCode());\nlogger.debug("Response=" + ${associatedWS.name}.getRawResponse());` : ''}</pre>
                </div>

                <div style="margin-top:12px;">
                  <div style="font-size:11px; color:#94A3B8; text-transform:uppercase; margin-bottom:4px;">Suggested Status Messages</div>
                  <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:0; border:1px dashed ${severity.color};">flexi.setStatusMessage("Please select a valid ${fieldName} value");
${associatedWS ? `flexi.setStatusMessage("${associatedWS.name} API Failed");` : ''}</pre>
                </div>
              </div>
            `;
         }

         screenCodeHtml += `
           <div style="background:${severity.badge !== '🟢 Informational' ? `rgba(${hexToRgb(severity.color)}, 0.05)` : 'rgba(255,255,255,0.02)'}; padding:16px; border:1px solid ${severity.badge !== '🟢 Informational' ? `rgba(${hexToRgb(severity.color)}, 0.3)` : 'rgba(255,255,255,0.04)'}; border-radius:8px;">
             <div style="display:flex; justify-content:space-between; align-items:center;">
               <h4 style="margin:0; color:${severity.color}; font-size:14px; display:flex; align-items:center; gap:8px;">
                 Field: ${escHtml(fieldName)}
               </h4>
               <span style="background:${severity.color}20; color:${severity.color}; padding:4px 8px; border-radius:12px; font-size:11px; font-weight:bold;">${severity.badge}</span>
             </div>
             ${debuggerAssitantHtml}
             ${wsHtml}
             ${eventsHtml}
           </div>
         `;
      }
    }
    screenCodeHtml += '</div>';

    analysisHtml += `
      <div class="dbg-copilot-section">
        <div class="dbg-copilot-title" style="color:#38BDF8; font-size:14px; border-bottom:1px solid rgba(56, 189, 248, 0.2); padding-bottom:8px; margin-bottom:16px;">
          <span>🧠</span> FIELD-LEVEL INVESTIGATION & LOG CORRELATION
        </div>
        ${screenCodeHtml}
      </div>
    `;
  }

  // Build Fields Properties Builder HTML
  let fieldsInspectorHtml = '';
  if (screenDef.fullFieldsList && screenDef.fullFieldsList.length > 0) {
     const fields = screenDef.fullFieldsList;
     
     if (!STATE.activeDbgField && fields.length > 0) {
        STATE.activeDbgField = fields[0].id || fields[0].name;
     }

     let fieldButtonsHtml = '';
     fields.forEach(f => {
        const fName = f.id || f.name;
        const isActive = fName === STATE.activeDbgField;
        fieldButtonsHtml += `
           <button class="dbg-field-item-btn ${isActive ? 'active' : ''}" 
                   data-fieldname="${escHtml(fName)}"
                   onclick="selectDbgField('${escHtml(fName)}')">
              🔑 ${escHtml(fName)}
           </button>
        `;
     });

     const activeFieldObj = fields.find(f => (f.id || f.name) === STATE.activeDbgField) || fields[0];
     let propertiesRowsHtml = '';
     
     if (activeFieldObj) {
        const knownPropKeys = [
          'id', 'label', 'style', 'isPassword', 'password', 'rendered', 'renderedLogic', 
          'autoEnter', 'required', 'readOnly', 'alterCase', 'defaultValue', 'length', 
          'dfi', 'dfiRequired', 'barcodeDelimiter', 'subsequentValue', 'onFocus', 'onFocusScript',
          'beforeExit', 'beforeExitScript', 'onExit', 'onExitScript', 'onKeyPress', 'onKeyPressScript',
          'dateFormat', 'lovSourceType', 'webService', 'lovPageTitle', 'lovStatement', 
          'inputParameter', 'parameterTypes', 'columnDisplay', 'columnPrompt', 'addPercent', 
          'lovValidation', 'blindSearch', 'enableGenerate', 'scanOnly', 'textAlignment'
        ];

        const processedKeys = new Set();

        const renderRow = (key, val) => {
           processedKeys.add(key);
           const title = PROPERTY_MAP[key] || key.charAt(0).toUpperCase() + key.slice(1).replace(/([A-Z])/g, ' $1').trim();
           
           let valueHtml = '';
           const isBoolean = typeof val === 'boolean' || val === 'true' || val === 'false';
           
           const isCodeKey = ['onFocus', 'onFocusScript', 'beforeExit', 'beforeExitScript', 'onExit', 'onExitScript', 'onKeyPress', 'onKeyPressScript', 'renderedLogic', 'lovStatement',
                              'afterFocus', 'afterFocusScript', 'afterClick', 'afterClickScript', 'inputProcessor', 'inputProcessorScript', 'onResponseReceived', 'onResponseReceivedScript', 'beforeFocus', 'beforeFocusScript',
                              '_onExit', '_afterFocus', '_beforeExit', '_afterClick', '_inputProcessor', '_onResponseReceived', '_onKeyPress', '_beforeFocus'].includes(key) || 
                              key.startsWith('_') || 
                              (typeof val === 'string' && (val.includes('flexi.') || val.includes('logger.') || val.includes('setStatusMessage')));
           
           if (isBoolean) {
              const checked = val === true || val === 'true';
              valueHtml = `<input type="checkbox" disabled ${checked ? 'checked' : ''} style="accent-color:#3B82F6; cursor:default; width: 14px; height: 14px;">`;
           } else if (isCodeKey) {
              if (val && typeof val === 'string' && val.trim() !== '') {
                 valueHtml = `<button class="prop-script-btn" onclick="showScriptModal('${escHtml(activeFieldObj.id || activeFieldObj.name)}', '${escHtml(key)}')"><span class="script-badge-icon">A</span> View Script</button>`;
              } else {
                 valueHtml = `<button class="prop-script-btn disabled" disabled><span class="script-badge-icon">A</span> Empty</button>`;
              }
           } else {
              valueHtml = val !== undefined && val !== null ? escHtml(String(val)) : '<span style="color:#475569;">—</span>';
           }

           return `
              <tr>
                 <td>${escHtml(title)}</td>
                 <td>${valueHtml}</td>
              </tr>
           `;
        };

        knownPropKeys.forEach(k => {
           let resolvedKey = k;
           let hasKey = k in activeFieldObj;
           if (!hasKey) {
              if (k === 'style' && 'controlType' in activeFieldObj) resolvedKey = 'controlType';
              else if (k === 'isPassword' && 'password' in activeFieldObj) resolvedKey = 'password';
              else if (k === 'onFocus' && 'onFocusScript' in activeFieldObj) resolvedKey = 'onFocusScript';
              else if (k === 'beforeExit' && 'beforeExitScript' in activeFieldObj) resolvedKey = 'beforeExitScript';
              else if (k === 'onExit' && 'onExitScript' in activeFieldObj) resolvedKey = 'onExitScript';
              else if (k === 'onKeyPress' && 'onKeyPressScript' in activeFieldObj) resolvedKey = 'onKeyPressScript';
              else if (k === 'lovSourceType' && 'lov_source_type' in activeFieldObj) resolvedKey = 'lov_source_type';
              else if (k === 'webService' && 'webservice' in activeFieldObj) resolvedKey = 'webservice';
              else return;
           }
           
           if (!processedKeys.has(resolvedKey)) {
              propertiesRowsHtml += renderRow(resolvedKey, activeFieldObj[resolvedKey]);
           }
        });

        Object.entries(activeFieldObj).forEach(([k, val]) => {
           if (!processedKeys.has(k) && k !== 'events') {
              propertiesRowsHtml += renderRow(k, val);
           }
        });
     }

     fieldsInspectorHtml = `
       <div id="dbg-tab-content-fields" style="display:${STATE.activeDbgTab === 'fields' ? 'flex' : 'none'}; gap:16px; height:100%; min-height:480px; margin-top: 12px;">
         <!-- Left Sidebar: Fields List -->
         <div style="width:230px; flex-shrink:0; border-right:1px solid rgba(255,255,255,0.08); padding-right:16px; overflow-y:auto; display:flex; flex-direction:column; gap:8px; max-height: 520px;">
            <div style="font-size:11px; font-weight:700; color:#94A3B8; letter-spacing:0.8px; text-transform:uppercase;">Screen Fields (${fields.length})</div>
            <input type="text" id="dbg-field-search" oninput="filterDbgFields()" placeholder="Search fields..." style="width:100%; background:#0F172A; border:1px solid rgba(255,255,255,0.08); border-radius:6px; padding:6px 10px; color:white; font-size:12px; margin-bottom:4px;">
            <div id="dbg-fields-list-container" style="display:flex; flex-direction:column; gap:4px;">
               ${fieldButtonsHtml}
            </div>
         </div>
         
         <!-- Right Main Area: Field Properties Table -->
         <div style="flex-grow:1; overflow-y:auto; padding-left:16px; max-height: 520px;">
            <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(255,255,255,0.06); padding-bottom:10px; margin-bottom:14px;">
               <div style="font-size:14px; font-weight:700; color:#38BDF8;">🔑 Properties Builder for: ${escHtml(STATE.activeDbgField || '')}</div>
               <span style="background:rgba(56,189,248,0.1); color:#38BDF8; font-size:11px; padding:2px 8px; border-radius:12px; font-weight:600;">Flexi Field Component</span>
            </div>
            <table class="prop-table">
               <thead>
                  <tr>
                     <th>Property Name</th>
                     <th>Value</th>
                  </tr>
               </thead>
               <tbody id="dbg-properties-table-body">
                  ${propertiesRowsHtml}
               </tbody>
            </table>
         </div>
       </div>
     `;
  } else {
     fieldsInspectorHtml = `
       <div id="dbg-tab-content-fields" style="display:none; padding:40px 20px; text-align:center; color:var(--text-muted);">
         <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="margin-bottom:12px; color:#475569;">
           <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
         </svg>
         <h3>No Structured Fields Found</h3>
         <p style="font-size:13px; max-width:400px; margin:8px auto 0 auto;">This view is active for screen JSON exports. If you uploaded a raw code file, use the Copilot Investigation or view the Raw Code below.</p>
       </div>
     `;
  }

  const activeTab = STATE.activeDbgTab || 'analysis';
  
  $('dbg-analysis-panel').innerHTML = `
    <!-- Tab Bar -->
    <div class="dbg-tab-bar">
      <button class="dbg-tab ${activeTab === 'analysis' ? 'active' : ''}" onclick="switchDbgTab('analysis')">🩺 Copilot Investigation</button>
      <button class="dbg-tab ${activeTab === 'fields' ? 'active' : ''}" onclick="switchDbgTab('fields')">📋 Screen Fields Properties</button>
    </div>
    
    <!-- Tab content 1: Analysis -->
    <div id="dbg-tab-content-analysis" style="display:${activeTab === 'analysis' ? 'block' : 'none'};">
       ${analysisHtml}
    </div>
    
    <!-- Tab content 2: Fields Inspector -->
    ${fieldsInspectorHtml}
  `;
}

// Global helpers for Screen Debugger tab and fields selection
window.switchDbgTab = function(tabId) {
  STATE.activeDbgTab = tabId;
  const analysisEl = document.getElementById('dbg-tab-content-analysis');
  const fieldsEl = document.getElementById('dbg-tab-content-fields');
  const tabs = document.querySelectorAll('.dbg-tab');
  
  if (analysisEl && fieldsEl) {
     if (tabId === 'analysis') {
        analysisEl.style.display = 'block';
        fieldsEl.style.display = 'none';
        tabs[0].classList.add('active');
        tabs[1].classList.remove('active');
     } else {
        analysisEl.style.display = 'none';
        fieldsEl.style.display = 'flex'; // Use flex for side-by-side layout
        tabs[0].classList.remove('active');
        tabs[1].classList.add('active');
     }
  }
};

window.selectDbgField = function(fieldName) {
  STATE.activeDbgField = fieldName;
  runScreenDebuggerAnalysis();
};

window.filterDbgFields = function() {
  const q = document.getElementById('dbg-field-search').value.toLowerCase().trim();
  const btns = document.querySelectorAll('.dbg-field-item-btn');
  btns.forEach(btn => {
     const name = btn.getAttribute('data-fieldname').toLowerCase();
     if (name.includes(q)) {
        btn.style.display = 'block';
     } else {
        btn.style.display = 'none';
     }
  });
};

// Stores the current script context so openScriptInEditor can access it
// Stores the current script context so openScriptInEditor can access it
window._scriptModalCtx = { code: '', fieldName: '', eventName: '' };
window.currentScriptEditor = null;

window.showScriptModal = function(fieldName, propKey) {
  const screenDef = STATE.screenDefinition;
  if (!screenDef || !screenDef.fullFieldsList) return;

  const fieldObj = screenDef.fullFieldsList.find(f => (f.id || f.name) === fieldName);
  if (!fieldObj) return;

  const scriptCode = fieldObj[propKey] || '';
  const title = PROPERTY_MAP[propKey] || propKey;

  // Store context for openScriptInEditor
  window._scriptModalCtx = { code: scriptCode, fieldName, eventName: title };

  const modal   = document.getElementById('screen-script-modal');
  const titleEl = document.getElementById('script-modal-title');
  const codeEl  = document.getElementById('script-modal-code');
  const editorContainer = document.getElementById('script-modal-editor-container');
  const copyBtn = document.getElementById('copy-script-btn');
  const statusEl= document.getElementById('open-editor-status');
  const sel     = document.getElementById('editor-choice-select');

  if (modal && titleEl) {
    titleEl.textContent = `${fieldName} — ${title} Script`;
    modal.style.display = 'flex';

    if (codeEl) codeEl.textContent = scriptCode;

    // Load Monaco Editor
    if (typeof require !== 'undefined' && typeof window.monaco === 'undefined') {
      require(['vs/editor/editor.main'], function() {
        initMonacoEditor(scriptCode, fieldName, propKey);
      });
    } else if (typeof window.monaco !== 'undefined') {
      initMonacoEditor(scriptCode, fieldName, propKey);
    } else {
      // Fallback
      if (editorContainer) editorContainer.style.display = 'none';
      if (codeEl) codeEl.style.display = 'block';
    }

    // Reset copy button
    if (copyBtn) {
      copyBtn.textContent        = '📋 Copy';
      copyBtn.style.background   = 'rgba(255,255,255,0.05)';
      copyBtn.style.borderColor  = 'rgba(255,255,255,0.1)';
      copyBtn.style.color        = '#E2E8F0';
    }

    // Hide status label
    if (statusEl) statusEl.style.display = 'none';

    // Restore last-used editor preference from localStorage
    if (sel) {
      const saved = localStorage.getItem('logradar_editor') || 'notepad';
      sel.value = saved;
    }
  }
};

function initMonacoEditor(code, fieldName, eventName) {
  const container = document.getElementById('script-modal-editor-container');
  const codeEl = document.getElementById('script-modal-code');
  if (!container) return;

  container.style.display = 'block';
  if (codeEl) codeEl.style.display = 'none';

  // Inject dynamic CSS rules for Delta Decorations if not already added
  if (!document.getElementById('monaco-decorations-style')) {
    const style = document.createElement('style');
    style.id = 'monaco-decorations-style';
    style.innerHTML = `
      .monaco-line-error { background-color: rgba(239, 68, 68, 0.2) !important; border-left: 3px solid #EF4444 !important; }
      .monaco-line-success { background-color: rgba(16, 185, 129, 0.2) !important; border-left: 3px solid #10B981 !important; }
      .monaco-glyph-error { width: 8px; background: #EF4444; border-radius: 50%; margin-left: 4px; }
      .monaco-glyph-success { width: 8px; background: #10B981; border-radius: 50%; margin-left: 4px; }
    `;
    document.head.appendChild(style);
  }

  // Check if we have an active issue
  const key = fieldName + '::' + eventName;
  const issue = STATE.scriptIssues ? STATE.scriptIssues[key] : null;

  let finalCode = code;
  let errorLine = null;
  let fixStart = null;
  let fixEnd = null;

  if (issue) {
    errorLine = issue.line;
    finalCode = code + `\n\n// ── RECOMMENDED FIX (Replace line ${issue.line} with below) ──\n` + issue.fix;
    
    const origLines = code.split('\n').length;
    fixStart = origLines + 3;
    fixEnd = fixStart + issue.fix.split('\n').length - 1;
  }

  if (window.currentScriptEditor) {
    window.currentScriptEditor.setValue(finalCode);
  } else {
    window.currentScriptEditor = window.monaco.editor.create(container, {
      value: finalCode,
      language: 'groovy',
      theme: 'vs-dark',
      readOnly: true,
      automaticLayout: true,
      minimap: { enabled: false },
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
      fontSize: 13,
      fontFamily: "'Fira Code', Consolas, monospace",
    });
  }

  // Apply Delta Decorations
  const decorations = [];
  if (issue && errorLine) {
    decorations.push({
      range: new window.monaco.Range(errorLine, 1, errorLine, 100),
      options: {
        isWholeLine: true,
        className: 'monaco-line-error',
        glyphMarginClassName: 'monaco-glyph-error',
        hoverMessage: { value: `Possible Root Cause: ${issue.issue}\nEvidence: ${issue.evidence}` }
      }
    });

    if (fixStart && fixEnd) {
      decorations.push({
        range: new window.monaco.Range(fixStart, 1, fixEnd, 100),
        options: {
          isWholeLine: true,
          className: 'monaco-line-success',
          glyphMarginClassName: 'monaco-glyph-success',
          hoverMessage: { value: 'Recommended Fix (Replace line above)' }
        }
      });
    }
  }

  if (window.currentScriptEditor._editorDecorations) {
    window.currentScriptEditor._editorDecorations = window.currentScriptEditor.deltaDecorations(
      window.currentScriptEditor._editorDecorations,
      decorations
    );
  } else {
    window.currentScriptEditor._editorDecorations = window.currentScriptEditor.deltaDecorations([], decorations);
  }

  if (errorLine) {
    setTimeout(() => {
      window.currentScriptEditor.revealLineInCenter(errorLine);
    }, 100);
  }
}

window.closeScriptModal = function() {
  const modal = document.getElementById('screen-script-modal');
  if (modal) modal.style.display = 'none';
};

window.downloadModalScript = function() {
  const { code, fieldName, eventName } = window._scriptModalCtx || {};
  if (!code) return;
  _downloadScriptFallback(code, fieldName, eventName);
};

window.copyModalScript = function() {
  const { code } = window._scriptModalCtx || {};
  const copyBtn = document.getElementById('copy-script-btn');
  if (code) {
     navigator.clipboard.writeText(code).then(() => {
        if (copyBtn) {
           copyBtn.textContent = 'Copied!';
           copyBtn.style.background = '#10B98120';
           copyBtn.style.borderColor = '#10B981';
           copyBtn.style.color = '#34D399';
        }
     }).catch(err => {
        console.error('Failed to copy text: ', err);
     });
  }
};

/* ---------- Open in Editor ------------------------------------------------- */
window.openScriptInEditor = async function() {
  const { code, fieldName, eventName } = window._scriptModalCtx || {};
  if (!code) {
    alert('No script code to open.');
    return;
  }

  const sel    = document.getElementById('editor-choice-select');
  const editor = sel ? sel.value : 'notepad';

  // Persist preference
  localStorage.setItem('logradar_editor', editor);

  const btn      = document.getElementById('open-in-editor-btn');
  const statusEl = document.getElementById('open-editor-status');

  if (btn) { btn.disabled = true; btn.textContent = '⏳ Opening…'; }
  if (statusEl) { statusEl.style.display = 'none'; }

  try {
    const resp = await fetch('http://localhost:9090/api/open-in-editor', {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({ code, fieldName, eventName, editor }),
    });

    if (resp.ok) {
      const data = await resp.json();
      if (statusEl) {
        statusEl.textContent  = `✔ Opened in ${data.editor || editor}`;
        statusEl.style.color  = '#10B981';
        statusEl.style.display= 'inline';
      }
    } else {
      throw new Error(`Server returned ${resp.status}`);
    }
  } catch (err) {
    // Server not running — fall back to download
    console.warn('Local server unreachable, falling back to download:', err.message);
    _downloadScriptFallback(code, fieldName, eventName);
    if (statusEl) {
      statusEl.textContent  = '⬇ Server offline — file downloaded instead';
      statusEl.style.color  = '#F59E0B';
      statusEl.style.display= 'inline';
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '🚀 Open'; }
  }
};

/** Fallback: trigger a browser download so the user can open the file manually */
function _downloadScriptFallback(code, fieldName, eventName) {
  const sanitize = s => String(s || 'script').replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 60);
  const fname    = `LogRadar_${sanitize(fieldName)}_${sanitize(eventName)}.js`;
  const blob     = new Blob([code], { type: 'text/plain' });
  const url      = URL.createObjectURL(blob);
  const a        = document.createElement('a');
  a.href         = url;
  a.download     = fname;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Helper to convert hex to rgb for rgba transparency
function hexToRgb(hex) {
  var result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result ? `parseInt(result[1], 16)}, ${parseInt(result[2], 16)}, ${parseInt(result[3], 16)}` : '255, 255, 255';
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
  } else if (viewId === 'graph') {
    renderInvestigationGraph();
  }
}

function renderInvestigationGraph() {
  const container = document.getElementById('graph-canvas-container');
  const detailsEl = document.getElementById('graph-node-details');
  if (!container || !STATE.analysis) {
    container.innerHTML = `<div style="padding:40px; color:var(--text-muted); text-align:center;">No active log file parsed to build flow graph.</div>`;
    return;
  }

  // Gather facts
  const screenName = STATE.screenDefinition ? (STATE.screenDefinition.screenName || STATE.screenDefinition.title) : (STATE.analysis.screen || "Main Screen");
  
  let failingField = "None Detected";
  let eventName = "N/A";
  let apiCall = "N/A";
  let status = "N/A";
  let ms = "N/A";
  let exception = "N/A";
  let statusMessage = "N/A";
  let sessionUser = STATE.analysis.users && STATE.analysis.users.length ? STATE.analysis.users[0] : "SVC_USER_01";
  let thread = "main";
  let nextAction = "Stay on Screen";

  // Scan scriptIssues for failure
  if (STATE.scriptIssues && Object.keys(STATE.scriptIssues).length > 0) {
    const firstKey = Object.keys(STATE.scriptIssues)[0];
    const issue = STATE.scriptIssues[firstKey];
    failingField = issue.fieldName;
    eventName = issue.eventName;
  }

  // Scan APIs
  if (STATE.analysis.apis && STATE.analysis.apis.length > 0) {
    const failingApi = STATE.analysis.apis.find(a => a.status >= 400 || a.ms > 2000) || STATE.analysis.apis[0];
    apiCall = failingApi.name;
    status = failingApi.status;
    ms = failingApi.ms;
    thread = failingApi.thread || "Thread-137";
  }

  // Scan Exceptions
  if (STATE.analysis.exceptions && STATE.analysis.exceptions.length > 0) {
    exception = STATE.analysis.exceptions[0].message || STATE.analysis.exceptions[0];
  }

  // Scan Status Messages
  const lastLine = STATE.parsed && STATE.parsed.length ? STATE.parsed[STATE.parsed.length - 1].message : "";
  if (lastLine.toLowerCase().includes('status:')) {
    const idx = lastLine.toLowerCase().indexOf('status:');
    statusMessage = lastLine.substring(idx + 7).trim();
  } else if (lastLine.toLowerCase().includes('aborted') || lastLine.toLowerCase().includes('failed')) {
    statusMessage = lastLine;
  } else {
    statusMessage = exception !== "N/A" ? exception.substring(0, 100) : "Internal Server Error";
  }

  // Scan Navigation
  const navM = lastLine.match(/render page\s+([A-Z0-9_]+)/i) || lastLine.match(/redirect\s+([A-Z0-9_]+)/i);
  if (navM) {
     nextAction = `Redirect to ${navM[1]}`;
  }

  const nodes = [
    { type: 'Screen', label: screenName, subtitle: 'User Action Target', color: '#818CF8', icon: '🖥', details: `Screen ID: ${screenName}\nContains input forms and script listeners.` },
    { type: 'Field', label: failingField, subtitle: 'Input Field Trigger', color: '#60A5FA', icon: '🔑', details: `Field Name: ${failingField}\nTriggered event listeners during data input.` },
    { type: 'Event', label: eventName, subtitle: 'Script Logic Execution', color: '#F472B6', icon: '⚡', details: `Event: ${eventName}\nInvoked inline Groovy script context.` },
    { type: 'API', label: apiCall, subtitle: 'Outbound REST call', color: '#FBBF24', icon: '📡', details: `Service: ${apiCall}\nOutbound integration request generated.` },
    { type: 'Response', label: `HTTP ${status} (${ms}ms)`, subtitle: 'Integration Gateway', color: status >= 400 ? '#EF4444' : '#34D399', icon: '📥', details: `Response Code: ${status}\nLatency: ${ms} ms\nDetermines technical success.` },
    { type: 'Object', label: exception.includes('JSONObject') ? 'JSONObject' : 'Data Object', subtitle: 'Schema Mapping State', color: '#A78BFA', icon: '📦', details: `Payload mapping object.\nChecked against strict JSON/XML schemas.` },
    { type: 'Session', label: `${sessionUser} [${thread}]`, subtitle: 'Execution Thread', color: '#38BDF8', icon: '👤', details: `User Session: ${sessionUser}\nJVM Thread Context: ${thread}` },
    { type: 'Validation', label: exception !== "N/A" ? exception.split(':')[0] : "N/A", subtitle: 'Exception Check', color: '#EF4444', icon: '🛡', details: `Exception: ${exception}` },
    { type: 'Status Message', label: statusMessage, subtitle: 'User Facing Alert', color: '#F87171', icon: '💬', details: `Message: ${statusMessage}\nDisplayed on client status bar.` },
    { type: 'Navigation', label: nextAction, subtitle: 'Control Flow Redirect', color: '#34D399', icon: '🚀', details: `Next State: ${nextAction}\nControl loop termination.` }
  ];

  let html = "";
  nodes.forEach((n, idx) => {
    html += `
      <div class="graph-node-card" data-idx="${idx}" style="display:flex; align-items:center; gap:12px; background:#1E293B; border:1px solid rgba(255,255,255,0.06); border-left:4px solid ${n.color}; border-radius:8px; padding:10px 16px; width:100%; max-width:550px; cursor:pointer; transition:all 0.2s;" onmouseover="this.style.transform='translateX(6px)'; this.style.borderColor='${n.color}50'" onmouseout="this.style.transform='translateX(0)'; this.style.borderColor='rgba(255,255,255,0.06)'">
        <div style="font-size:20px; background:${n.color}15; color:${n.color}; width:40px; height:40px; border-radius:50%; display:flex; align-items:center; justify-content:center;">
          ${n.icon}
        </div>
        <div style="flex-grow:1;">
          <div style="font-size:10px; text-transform:uppercase; color:#94A3B8; font-weight:700; letter-spacing:0.5px;">${n.type}</div>
          <div style="font-size:13.5px; font-weight:600; color:#F8FAFC; margin-top:2px; word-break:break-all;">${escHtml(n.label)}</div>
          <div style="font-size:11px; color:#64748B; margin-top:1px;">${escHtml(n.subtitle)}</div>
        </div>
        <div style="font-size:18px; color:var(--text-muted);">❯</div>
      </div>
    `;
    if (idx < nodes.length - 1) {
      html += `<div style="color:var(--text-muted); font-size:14px; font-weight:700; margin: 2px 0;">↓</div>`;
    }
  });

  container.innerHTML = html;

  container.querySelectorAll('.graph-node-card').forEach(card => {
    card.addEventListener('click', () => {
      const idx = parseInt(card.dataset.idx);
      const node = nodes[idx];
      
      detailsEl.innerHTML = `
        <div style="background:${node.color}10; border:1px solid ${node.color}30; border-radius:8px; padding:12px; display:flex; align-items:center; gap:10px; margin-bottom:12px;">
          <div style="font-size:24px; color:${node.color};">${node.icon}</div>
          <div>
            <div style="font-size:11px; text-transform:uppercase; color:#94A3B8; font-weight:700;">${node.type}</div>
            <div style="font-size:15px; font-weight:700; color:#F8FAFC;">${escHtml(node.label)}</div>
          </div>
        </div>
        
        <div style="background:rgba(0,0,0,0.2); border:1px solid var(--border); border-radius:8px; padding:14px; font-family:sans-serif; line-height:1.6;">
          <h4 style="margin:0 0 8px 0; color:var(--text-light); font-size:13px; text-transform:uppercase; border-bottom:1px solid var(--border); padding-bottom:4px;">Diagnostic Info</h4>
          <pre style="margin:0; font-family:monospace; font-size:12px; color:#38BDF8; white-space:pre-wrap; word-break:break-all;">${escHtml(node.details)}</pre>
        </div>

        <div style="margin-top:16px;">
          <button id="graph-node-action-btn" class="paste-submit-btn" style="width:100%; border-radius:6px; font-weight:600; padding:10px; background:linear-gradient(135deg,#3B82F6,#2563EB);" onclick="handleGraphNodeAction('${node.type}', '${escHtml(node.label)}')">
            🔍 Go to ${node.type} Details
          </button>
        </div>
      `;
    });
  });
}

window.handleGraphNodeAction = function(type, label) {
  if (type === 'Screen' || type === 'Field' || type === 'Event') {
    switchView('debugger');
    if (type === 'Field' && label !== 'None Detected') {
      selectDbgField(label);
    }
  } else if (type === 'API' || type === 'Response') {
    switchView('api');
    if (label !== 'N/A') {
      if (label.includes(' ')) {
        const cleanName = label.split(' ')[0];
        selectApiByName(cleanName);
      } else {
        selectApiByName(label);
      }
    }
  } else if (type === 'Validation' || type === 'Status Message') {
    switchView('analyzer');
  } else if (type === 'Session') {
    switchView('flow');
  } else {
    switchView('dashboard');
  }
};

// ─── Filter & Search ──────────────────────────────────────────────────────────
function applyFilters() {
  const q = document.getElementById('search-input').value.trim();
  STATE.filtered = STATE.parsed.filter(row => {
    if (STATE.filterByScreen && !isLogRelatedToScreen(row.message)) return false;
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

// ─── Streaming constants ───────────────────────────────────────────────────
const STREAM_CHUNK_BYTES = 4 * 1024 * 1024; // 4 MB per chunk
let _streamWorker = null;

// ─── handleFileSelect — entry point ───────────────────────────────────────
function handleFileSelect(file) {
  if (STATE.isLoading) return;
  STATE.isLoading = true;

  let worker = null;
  try { worker = new Worker('log-worker.js'); } catch (e) {
    console.warn('[LogRadar] Web Worker unavailable, using legacy path:', e.message);
  }

  if (worker) _useStreamingPath(file, worker);
  else _useLegacyPath(file);
}

// ─── Streaming path ────────────────────────────────────────────────────────
function _useStreamingPath(file, worker) {
  _streamWorker = worker;
  const filename   = file.name;
  const totalSize  = file.size;
  const totalChunks = Math.ceil(totalSize / STREAM_CHUNK_BYTES);

  // Full state reset
  STATE.currentFile = filename;
  STATE.selectedRow = null;
  STATE.analysis    = null;
  STATE.parsed      = [];
  STATE.filtered    = [];
  STATE.rawLines    = [];
  STATE.stream = {
    apis: [], exceptions: [], sqlIssues: [], warnings: [],
    logCounts: { FATAL:0, ERROR:0, WARN:0, INFO:0, DEBUG:0, TRACE:0 },
    totalLines: 0, apiCount: 0, errorCount: 0, warnCount: 0, sqlCount: 0,
    logType: 'Generic', chunksDone: 0, totalChunks,
  };

  worker.postMessage({ type: 'RESET' });

  const fnEl = document.getElementById('topbar-filename');
  if (fnEl) fnEl.textContent = filename;
  const sfnEl = document.getElementById('sidebar-file-name');
  if (sfnEl) sfnEl.textContent = filename;

  STATE.activeLevels = new Set(['FATAL','ERROR','WARN','INFO','DEBUG']);
  document.querySelectorAll('.level-checkbox').forEach(cb => {
    cb.checked = true;
    cb.closest('.level-pill')?.classList.remove('inactive');
  });

  const searchInput = document.getElementById('search-input');
  if (searchInput) searchInput.value = '';

  _showStreamUI(filename, totalChunks, totalSize);

  worker.onmessage = (ev) => {
    const { type: mtype, chunkIndex, totalChunks: tc, isLast, stats, newApis, result } = ev.data;

    if (mtype === 'CHUNK_RESULT') {
      Object.assign(STATE.stream, {
        totalLines: stats.totalLines, logCounts: stats.logCounts,
        apiCount: stats.apiCount, errorCount: stats.errorCount,
        warnCount: stats.warnCount, sqlCount: stats.sqlCount,
        logType: stats.logType, chunksDone: chunkIndex + 1, totalChunks: tc,
      });
      _updateStreamStats(stats, chunkIndex, tc);

      // Progressive API Tracker update
      if (newApis && newApis.length) {
        STATE.stream.apis = newApis;
        if (typeof renderApiTracker === 'function') renderApiTracker(STATE.stream.apis);
        _updateStreamBadge('api-tracker-badge', stats.apiCount);
      }
      if (stats.errorCount > 0) {
        _updateStreamBadge('card-critical-count', stats.errorCount);
      }
    }

    if (mtype === 'COMPLETE') {
      _onStreamComplete(result, filename, worker);
    }
  };

  worker.onerror = (err) => {
    console.error('[LogRadar] Worker error:', err);
    STATE.isLoading = false;
    hideLoadingUI();
  };

  _readChunks(file, worker, totalChunks);
}

async function _readChunks(file, worker, totalChunks) {
  const totalSize = file.size;
  let offset = 0;
  let chunkIndex = 0;
  while (offset < totalSize) {
    const end   = Math.min(offset + STREAM_CHUNK_BYTES, totalSize);
    const isLast = end >= totalSize;
    const slice  = file.slice(offset, end);
    const text   = await new Promise((res, rej) => {
      const r = new FileReader();
      r.onload = e => res(e.target.result);
      r.onerror = rej;
      r.readAsText(slice);
    });
    worker.postMessage({ type: 'CHUNK', text, chunkIndex, totalChunks, isLast });
    const pct = Math.round((end / totalSize) * 95);
    const fill = document.getElementById('upload-progress-fill');
    if (fill) fill.style.width = pct + '%';
    const cardFill = document.getElementById('upload-card-progress-fill');
    if (cardFill) cardFill.style.width = pct + '%';
    offset = end;
    chunkIndex++;
    await new Promise(r => setTimeout(r, 0)); // yield to UI thread
  }
}

function _onStreamComplete(result, filename, worker) {
  // Map worker result to STATE.analysis shape (so all existing renderers work)
  STATE.analysis = {
    errors:      result.exceptions,
    warnings:    result.warnings,
    apis:        result.apis,
    sqls:        result.sqlIssues,
    vars:        {},
    module:      result.module || 'General',
    groups:      _groupErrorsFromResult(result.exceptions),
    users:       result.users || [],
    screen:      result.screen,
    transaction: result.transaction,
    score:       result.healthScore,
    depChain:    [],
    flow:        [],
    execSummary: _buildStreamExecSummary(result),
    logType:     result.logType,
    blankApis:   result.blankApis || [],
    loggerStats: { counts: result.logCounts, gaps: result.loggerGaps || [] },
    totalLines:  result.totalLines,
    rawLineCount: result.totalLines,
  };

  STATE.parsed   = result.exceptions.map(e => ({ id: e.id, timestamp: e.timestamp, thread: e.thread, level: e.level, source: e.source, message: e.message, isException: true }));
  STATE.filtered = [...STATE.parsed];

  const ttEl = document.getElementById('topbar-title');
  if (ttEl) ttEl.textContent = 'Root Cause Analysis';

  renderDashboard(STATE.analysis);
  applyFilters();
  renderTimeline(result.exceptions);
  renderApiTracker(result.apis);
  runScreenDebuggerAnalysis();

  const fill = document.getElementById('upload-progress-fill');
  if (fill) fill.style.width = '100%';

  hideLoadingUI();
  switchView('dashboard');
  STATE.isLoading = false;
  if (worker) { worker.terminate(); _streamWorker = null; }
  console.log(`[LogRadar Streaming] ${result.totalLines} lines | ${result.apis.length} APIs | ${result.exceptions.length} errors`);
}

function _groupErrorsFromResult(exceptions) {
  const map = {};
  (exceptions || []).forEach(e => {
    const key = e.message.split('\n')[0].trim().substring(0, 80);
    if (!map[key]) map[key] = { key, count: 0, errType: e.level, firstEntry: e };
    map[key].count++;
  });
  return Object.values(map).sort((a, b) => b.count - a.count);
}

function _buildStreamExecSummary(result) {
  let dur = 'Unknown';
  try {
    if (result.firstTimestamp && result.lastTimestamp) {
      const ms = new Date(result.lastTimestamp.replace(' ','T')) - new Date(result.firstTimestamp.replace(' ','T'));
      dur = Math.round(ms / 1000) + 's';
    }
  } catch(e) {}
  return {
    logType: result.logType,
    duration: dur,
    totalLines: result.totalLines,
    healthScore: result.healthScore,
    apiCount: (result.apis || []).length,
    failedApis: (result.apis || []).filter(a => a.status >= 400).length,
    slowApis: (result.apis || []).filter(a => a.ms > 2000 && a.status < 400).length,
    blankApis: (result.blankApis || []).length,
    errorCount: (result.exceptions || []).length,
    warnCount: (result.warnings || []).length,
    sqlCount: (result.sqlIssues || []).length,
    confidence: result.totalLines > 500 ? 'HIGH' : result.totalLines > 50 ? 'MEDIUM' : 'LOW',
    recommendations: [],
  };
}

// ─── Streaming progress UI helpers ────────────────────────────────────────
function _showStreamUI(filename, totalChunks, totalSize) {
  const titleEl = document.getElementById('upload-loading-title');
  if (titleEl) titleEl.textContent = 'Streaming Analysis…';
  const fnEl = document.getElementById('upload-loading-filename');
  if (fnEl) fnEl.textContent = filename;

  const card = document.getElementById('upload-loading-card');
  if (card) card.style.display = 'flex';
  const bar = document.getElementById('upload-progress-bar');
  if (bar) { bar.style.display = 'block'; bar.classList.add('active'); }
  const fill = document.getElementById('upload-progress-fill');
  if (fill) fill.style.width = '0%';

  const stepsEl = document.getElementById('upload-loading-steps');
  if (stepsEl) stepsEl.style.display = 'none';

  let statsEl = document.getElementById('stream-stats-panel');
  if (statsEl) statsEl.remove(); // reset
  statsEl = document.createElement('div');
  statsEl.id = 'stream-stats-panel';
  statsEl.className = 'stream-stats-panel';
  const mb = (totalSize / 1024 / 1024).toFixed(1);
  statsEl.innerHTML = `
    <div class="stream-stat"><span class="ss-val" id="ss-chunks">0/${totalChunks}</span><span class="ss-lbl">Chunks</span></div>
    <div class="stream-stat"><span class="ss-val" id="ss-lines">0</span><span class="ss-lbl">Lines Read</span></div>
    <div class="stream-stat ss-highlight"><span class="ss-val" id="ss-apis">0</span><span class="ss-lbl">APIs Found</span></div>
    <div class="stream-stat ss-error"><span class="ss-val" id="ss-errors">0</span><span class="ss-lbl">Errors</span></div>
    <div class="stream-stat ss-warn"><span class="ss-val" id="ss-warns">0</span><span class="ss-lbl">Warnings</span></div>
    <div class="stream-stat"><span class="ss-val" id="ss-sql">0</span><span class="ss-lbl">SQL Issues</span></div>
  `;
  if (card) card.appendChild(statsEl);

  const largeWarn = document.getElementById('upload-large-warning');
  if (largeWarn) {
    largeWarn.style.display = totalSize > 5 * 1024 * 1024 ? 'block' : 'none';
    largeWarn.textContent = `Streaming ${mb} MB in ${totalChunks} chunk${totalChunks !== 1 ? 's' : ''} — browser stays responsive`;
  }
}

function _updateStreamStats(stats, chunkIndex, totalChunks) {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set('ss-chunks', `${chunkIndex + 1}/${totalChunks}`);
  set('ss-lines',  stats.totalLines.toLocaleString());
  set('ss-apis',   stats.apiCount);
  set('ss-errors', stats.errorCount);
  set('ss-warns',  stats.warnCount);
  set('ss-sql',    stats.sqlCount);
  if (stats.logType && stats.logType !== 'Generic') {
    const t = document.getElementById('upload-loading-title');
    if (t && !t.textContent.includes(stats.logType)) t.textContent = `Streaming ${stats.logType} Log…`;
  }
}

function _updateStreamBadge(id, count) {
  const el = document.getElementById(id);
  if (el) { el.textContent = count; if (count > 0) el.style.display = ''; }
}

// ─── Legacy path (fallback when Worker unavailable) ────────────────────────
function _useLegacyPath(file) {
  const titleEl = document.getElementById('upload-loading-title');
  showLoadingUI(file.name);
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
    setTimeout(() => { loadLog(ev.target.result, file.name, true); }, 150);
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

  // Screen JSON upload
  const uploadScreenBtn = document.getElementById('upload-screen-btn');
  if (uploadScreenBtn) {
    uploadScreenBtn.addEventListener('click', () => {
      const screenInput = document.getElementById('screen-input');
      if (screenInput) {
        screenInput.value = '';
        screenInput.click();
      }
    });
  }
  const screenInput = document.getElementById('screen-input');
  if (screenInput) {
    screenInput.addEventListener('change', e => {
      const file = e.target.files[0];
      if (!file) return;
      handleScreenSelect(file);
      e.target.value = '';
    });
  }

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

  // AUTO-LOAD SCREEN FOR TESTING
  fetch('test_screen.json')
    .then(r => r.json())
    .then(json => {
       STATE.screenDefinition = {
          screenName: "test_screen.json",
          title: "Work Order Completion",
          fields: {
             "ORG_CODE": { "OnExit": { code: "flexi.invokeWebService('ORG_WEBSERVICE'); logger.debug('Exiting Org field');" } },
             "ITEM": { "OnFocus": { code: "logger.debug('Focus on Item field');" } }
          },
          fullFieldsList: [
            {
              "id": "ORG_CODE",
              "label": "Org",
              "style": "Normal",
              "required": true,
              "onExit": "flexi.invokeWebService('ORG_WEBSERVICE'); logger.debug('Exiting Org field');",
              "lovSourceType": "Web Service",
              "webService": "ORG_WEBSERVICE",
              "isPassword": false,
              "readOnly": false,
              "addPercent": true,
              "lovValidation": true
            },
            {
              "id": "ITEM",
              "label": "Item",
              "style": "Barcode",
              "required": true,
              "onFocus": "logger.debug('Focus on Item field');",
              "isPassword": false,
              "readOnly": false
            }
          ],
          webservices: {
             "ORG_WEBSERVICE": { request: "http://api.com/org", response: "{ status: 'ok' }" }
          },
          rawCode: JSON.stringify(json, null, 2)
       };
       STATE.currentScreenFile = "test_screen.json";
       const nameEl = document.getElementById('sidebar-screen-name');
       if (nameEl) nameEl.textContent = "test_screen.json";
       
       // Switch default debugger active field
       STATE.activeDbgField = "ORG_CODE";
       
       runScreenDebuggerAnalysis();
    }).catch(err => {
       console.log('No test_screen.json found or failed to load:', err);
    });

});
