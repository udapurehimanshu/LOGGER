// ═══════════════════════════════════════════════════════════════════════════
//  LogRadar AI — Streaming Log Worker
//  Runs in a Web Worker thread. Receives text chunks, parses + analyses
//  incrementally, posts results back. Never holds the full file in memory.
// ═══════════════════════════════════════════════════════════════════════════
'use strict';

// ─── Knowledge Bases (self-contained — worker has no access to main thread) ─
const EXCEPTION_KB = {
  NullPointerException:           { short: 'Null Reference',         errType: 'Runtime Error' },
  ClassCastException:             { short: 'Type Mismatch',          errType: 'Runtime Error' },
  ArrayIndexOutOfBoundsException: { short: 'Array Bounds',           errType: 'Runtime Error' },
  IndexOutOfBoundsException:      { short: 'List Index Out of Range',errType: 'Runtime Error' },
  NumberFormatException:          { short: 'Invalid Number Format',  errType: 'Validation Error' },
  TargetError:                    { short: 'Script Engine Error',    errType: 'Script Error' },
  SQLException:                   { short: 'Database Query Error',   errType: 'Database Error' },
  JSONException:                  { short: 'JSON Parse Error',       errType: 'Integration Error' },
  ParseException:                 { short: 'Data Parse Failure',     errType: 'Validation Error' },
  IllegalArgumentException:       { short: 'Invalid Argument',       errType: 'Validation Error' },
};

const MODULE_KB = {
  'API Layer':       ['REST', 'HTTP', 'endpoint', 'callWebService', 'HttpClient', 'Request Method', 'Response Code', 'API', 'service', 'RestClient'],
  'Database Layer':  ['SQL', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'ORA-', 'SQLException', 'QueryEngine', 'Connection', 'jdbc', 'executeQuery'],
  'Auth Layer':      ['auth', 'login', 'token', 'forbidden', 'unauthorized', '403', '401', 'Security', 'privilege'],
  'Script Engine':   ['TargetError', 'inline evaluation', 'bsh.', 'ScriptExecutor', 'ScriptEngine', 'FIELD_VALIDATION'],
  'Integration':     ['integration', 'callback', 'Receiver', 'correlation', 'sync', 'inbound', 'outbound'],
  'Messaging':       ['kafka', 'rabbitmq', 'queue', 'topic', 'event', 'broker'],
  'Background Jobs': ['scheduler', 'cron', 'batch', 'worker'],
  'Caching Layer':   ['cache', 'redis', 'memcache', 'evict'],
};

// ─── Worker State (persists across chunks) ──────────────────────────────────
const WS = {
  currentEntry: null,
  entryId: 0,
  lineTail: '',
  apis: [],
  exceptions: [],
  sqlIssues: [],
  warnings: [],
  timeline: [],
  logCounts: { FATAL: 0, ERROR: 0, WARN: 0, INFO: 0, DEBUG: 0, TRACE: 0 },
  totalLines: 0,
  threadContexts: {},
  threadLastTimes: {},
  threadApiStates: {},
  dbStarts: 0,
  dbEnds: 0,
  logTypeHints: { flexi: 0, spring: 0, python: 0, node: 0, log4j: 0 },
  logType: 'Generic',
  firstTimestamp: null,
  lastTimestamp: null,
  users: new Set(),
  screen: null,
  transaction: null,
  module: null,
  moduleScores: {},
};

// ─── Regex Patterns ───────────────────────────────────────────────────────────
const RE_M1  = /^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(.+)$/i;
const RE_M1B = /^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(.+)$/i;
const RE_M2  = /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s+(\S+)\s+-\s+(.+)$/i;
const RE_M3  = /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(.+)$/i;
const RE_M4  = /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\s+(.+)$/i;
const RE_M5  = /^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(.+)$/i;
const RE_EXCEPTION = /Exception|Error:|FATAL|ORA-\d{5}|TargetError/i;
const RE_RESP_CODE = /Response Code\s*[=:]\s*(4\d{2}|5\d{2})/i;

// ─── Line Parser ─────────────────────────────────────────────────────────────
function parseLine(line) {
  let m;
  m = line.match(RE_M1);
  if (m) return { timestamp: m[2], thread: m[3], level: m[1].toUpperCase(), source: m[4], message: m[5] };
  m = line.match(RE_M1B);
  if (m) return { timestamp: m[2], thread: m[3], level: m[1].toUpperCase(), source: 'Unknown', message: m[4] };
  m = line.match(RE_M2);
  if (m) return { timestamp: m[1], thread: m[2], level: m[3].toUpperCase(), source: m[4], message: m[5] };
  m = line.match(RE_M3);
  if (m) return { timestamp: m[1], thread: m[3], level: m[2].toUpperCase(), source: m[4], message: m[5] };
  m = line.match(RE_M4);
  if (m) return { timestamp: m[1], thread: m[2], level: 'INFO', source: 'Unknown', message: m[3] };
  m = line.match(RE_M5);
  if (m) return { timestamp: '', thread: 'main', level: m[1].toUpperCase(), source: 'Unknown', message: m[2] };
  return null;
}

// ─── Warning classification ───────────────────────────────────────────────────
function classifyWarning(msgL) {
  if (msgL.includes('config') || msgL.includes('property') || msgL.includes('missing setting'))
    return { type: 'Configuration Warning', impact: 'Misconfigured settings may lead to fallback behaviors.', future: false };
  if (msgL.includes('deprecat') || msgL.includes('obsolete'))
    return { type: 'Deprecated API', impact: 'Depends on deprecated APIs that will be removed.', future: true };
  if (msgL.includes('memory') || msgL.includes('heap') || msgL.includes('leak'))
    return { type: 'Memory Warning', impact: 'Elevated memory usage. Risk of OutOfMemory crash.', future: true };
  if (msgL.includes('slow') || msgL.includes('latency') || msgL.includes('timeout') || msgL.includes('performance'))
    return { type: 'Performance Warning', impact: 'High latency may degrade user experience.', future: false };
  if (msgL.includes('security') || msgL.includes('auth') || msgL.includes('unauthorized') || msgL.includes('permission'))
    return { type: 'Security Warning', impact: 'Potential vulnerability or unauthorized access.', future: false };
  if (msgL.includes('sql') || msgL.includes('database') || msgL.includes('jdbc') || msgL.includes('oracle'))
    return { type: 'Database Warning', impact: 'Database queries or connections are slow.', future: true };
  if (msgL.includes('network') || msgL.includes('socket') || msgL.includes('connect') || msgL.includes('refused'))
    return { type: 'Network Warning', impact: 'Transient network issues detected.', future: false };
  return { type: 'General Warning', impact: 'Potential system degradation.', future: false };
}

// ─── API Extraction (stateful) ────────────────────────────────────────────────
function processApiLine(e) {
  const thread = e.thread;
  const msg = e.message;
  if (!WS.threadContexts[thread]) WS.threadContexts[thread] = { currentApi: null };
  const ctx = WS.threadContexts[thread];

  const hasCallWS = msg.includes('callWebService');
  const hasRunWS  = msg.includes('runWebService');
  const hasInit   = msg.includes('Initiating API call');

  let nameM = null;
  if (hasCallWS || hasInit) {
    nameM = msg.match(/callWebService:name:(\S+)/i) ||
            msg.match(/Initiating API call:\s*(\S+)/i) ||
            msg.match(/(\S+)\.callWebService\(\)\s*started/i);
  }
  let runWsStart = null;
  if (!nameM && hasRunWS) {
    runWsStart = msg.match(/^([A-Za-z0-9_]+)\.runWebService\s*$/i);
    if (!runWsStart) runWsStart = msg.match(/[\s\-]([A-Za-z0-9_]+)\.runWebService\s*$/i);
  }

  if (nameM || runWsStart) {
    const apiName = nameM ? nameM[1] : runWsStart[1];
    if (ctx.currentApi) WS.apis.push(ctx.currentApi);
    ctx.currentApi = {
      name: apiName, endpoint: null, method: 'GET',
      status: null, ms: 0, request: null, response: null,
      timestamp: e.timestamp, thread, logIndex: e.id,
    };
    return;
  }

  if (!ctx.currentApi) return;

  if (msg.includes('URL') || msg.includes('Endpoint')) {
    const urlM = msg.match(/URL\s*=\s*(https?:\/\/\S+)/i) || msg.match(/URL\s*=\s*(\S+)/i);
    if (urlM) ctx.currentApi.endpoint = urlM[1];
  }
  if (msg.includes('Request Method')) {
    const mM = msg.match(/Request Method\s*=\s*(\S+)/i);
    if (mM) ctx.currentApi.method = mM[1];
  }
  if (msg.includes('Response Code') || msg.includes('HTTP Response Code')) {
    const sM = msg.match(/Response Code\s*[=:]\s*(\d+)/i) || msg.match(/HTTP Response Code\s*:\s*(\d+)/i);
    if (sM) ctx.currentApi.status = parseInt(sM[1]);
  }
  if (hasRunWS && msg.includes('result')) {
    const rsM = msg.match(/\.runWebService:\s*result\s+(\d{3})/i);
    if (rsM) {
      ctx.currentApi.status = parseInt(rsM[1]);
      const bi = msg.indexOf('{', msg.indexOf('result'));
      if (bi !== -1) ctx.currentApi.response = msg.substring(bi, bi + 2000);
    }
  }
  if (msg.includes('Total time')) {
    const tM = msg.match(/Total time\s*=\s*(\d+)/i);
    if (tM) ctx.currentApi.ms = parseInt(tM[1]);
  } else if (hasCallWS) {
    const tM = msg.match(/callWebService\(\)\s*:\s*(\d+)/i);
    if (tM) ctx.currentApi.ms = parseInt(tM[1]);
  }
  if (msg.includes('Response Body')) {
    const rM = msg.match(/Response Body\s*:\s*(.+)$/is);
    if (rM) ctx.currentApi.response = rM[1].substring(0, 2000);
  }
  if (hasRunWS && msg.includes('Total time') && ctx.currentApi) {
    WS.apis.push(ctx.currentApi);
    ctx.currentApi = null;
  }
}

// ─── Process a completed log entry ────────────────────────────────────────────
function processEntry(e) {
  if (!e) return;
  e.id = WS.entryId++;
  e.isException = RE_EXCEPTION.test(e.message) || RE_RESP_CODE.test(e.message);
  if (RE_RESP_CODE.test(e.message)) e.level = 'ERROR';

  const lvl = e.level;
  if (WS.logCounts[lvl] !== undefined) WS.logCounts[lvl]++;
  WS.totalLines++;

  if (e.timestamp) {
    if (!WS.firstTimestamp) WS.firstTimestamp = e.timestamp;
    WS.lastTimestamp = e.timestamp;
  }

  WS.timeline.push({ id: e.id, ts: e.timestamp, level: e.level, source: e.source });

  const msgL = e.message.toLowerCase();
  if (msgL.includes('useractionlogger') || msgL.includes('intellinum') || msgL.includes('flexiruntime')) WS.logTypeHints.flexi++;
  if (msgL.includes(':: spring boot ::') || msgL.includes('org.springframework')) WS.logTypeHints.spring++;
  if (msgL.includes('traceback (most recent call last)')) WS.logTypeHints.python++;
  if (msgL.includes('node_modules') || msgL.includes('node:internal')) WS.logTypeHints.node++;
  if (msgL.includes('log4j') || msgL.includes('org.apache.log4j')) WS.logTypeHints.log4j++;

  const msg = e.message;
  const uM = msg.match(/User:\s*([A-Z0-9_]+)/i); if (uM) WS.users.add(uM[1]);
  if (!WS.screen) { const sm = msg.match(/Screen:\s*([A-Z0-9_]+)/i); if (sm) WS.screen = sm[1]; }
  if (!WS.transaction) { const tm = msg.match(/[Tt]ransaction:\s*([^\n,\.]+)/); if (tm) WS.transaction = tm[1].trim(); }

  for (const [mod, kws] of Object.entries(MODULE_KB)) {
    if (!WS.moduleScores[mod]) WS.moduleScores[mod] = 0;
    for (const kw of kws) { if (msg.includes(kw)) { WS.moduleScores[mod]++; break; } }
  }

  if ((lvl === 'ERROR' || lvl === 'FATAL') && WS.exceptions.length < 5000) {
    WS.exceptions.push({ id: e.id, timestamp: e.timestamp, thread: e.thread, level: e.level, source: e.source, message: msg.substring(0, 1000) });
  }

  const oraPat = /ORA-(\d{5})/gi;
  let oraMt;
  while ((oraMt = oraPat.exec(msg)) !== null) WS.sqlIssues.push({ code: oraMt[1], col: null, sql: null });
  const jPat = /JSONObject\["([^"]+)"\]\s+not found/gi;
  let jmt;
  while ((jmt = jPat.exec(msg)) !== null) WS.sqlIssues.push({ code: 'JSON_KEY_MISSING', col: jmt[1], sql: null });

  if (lvl === 'WARN' && WS.warnings.length < 2000) {
    const cl = classifyWarning(msgL);
    WS.warnings.push({ id: e.id, timestamp: e.timestamp, source: e.source, message: msg.substring(0, 500), classification: cl.type, impact: cl.impact, causesFutureFailure: cl.future });
  }

  if (msgL.includes('executequery') || msgL.includes('select ') || msgL.includes('insert ') || msgL.includes('update ')) WS.dbStarts++;
  if (msgL.includes('rows fetched') || msgL.includes('query complete') || msgL.includes('rows affected')) WS.dbEnds++;

  processApiLine(e);
}

// ─── Flush multi-line entry ───────────────────────────────────────────────────
function flushEntry(newParsed) {
  const done = WS.currentEntry;
  WS.currentEntry = newParsed;
  return done;
}

// ─── Process a chunk ─────────────────────────────────────────────────────────
function processChunk(text, isLast) {
  const fullText = WS.lineTail + text;
  const lines = fullText.split(/\r?\n/);

  if (!isLast && lines.length > 0) {
    WS.lineTail = lines.pop();
  } else {
    WS.lineTail = '';
  }

  for (const line of lines) {
    if (!line.trim()) continue;
    const p = parseLine(line);
    if (p) {
      const done = flushEntry(p);
      if (done) processEntry(done);
    } else if (WS.currentEntry) {
      WS.currentEntry.message += '\n' + line;
    }
  }

  if (isLast && WS.currentEntry) {
    processEntry(WS.currentEntry);
    WS.currentEntry = null;
  }
}

// ─── Finalize after all chunks ────────────────────────────────────────────────
function finalizeState() {
  // Flush remaining open API contexts
  for (const t in WS.threadContexts) {
    if (WS.threadContexts[t].currentApi) {
      WS.apis.push(WS.threadContexts[t].currentApi);
      WS.threadContexts[t].currentApi = null;
    }
  }

  // Log type
  const h = WS.logTypeHints;
  if (h.flexi > 0) WS.logType = 'Flexi Runtime';
  else if (h.spring > 0) WS.logType = 'Spring Boot';
  else if (h.python > 0) WS.logType = 'Python';
  else if (h.node > 0)   WS.logType = 'NodeJS';
  else if (h.log4j > 0)  WS.logType = 'Apache Log4j';
  else WS.logType = 'Generic';

  // Module
  const best = Object.entries(WS.moduleScores).sort((a, b) => b[1] - a[1])[0];
  WS.module = (best && best[1] > 0) ? best[0] : 'General';

  // Post-process APIs
  WS.apis.forEach(api => {
    if (!api.status) api.status = 200;
    if (!api.businessResult) {
      if (api.status >= 400) { api.businessResult = `Failed (HTTP ${api.status})`; }
      else if (api.response) {
        const r = api.response;
        if (r.includes('"success":false') || r.includes('"valid":false')) api.businessResult = 'Business Validation Failure';
        else if (r.trim() === '[]' || r.trim() === '{}' || /\"count\"\s*:\s*0\b/i.test(r) || /\"items\"\s*:\s*\[\s*\]/i.test(r)) api.businessResult = 'Blank Response';
        else api.businessResult = 'Healthy';
      } else api.businessResult = 'Healthy';
    }
    if (!api.endpoint && api.response) {
      const hM = api.response.match(/"href"\s*:\s*"([^"]+)"/i);
      if (hM) api.endpoint = hM[1];
    }
    if (api.response) {
      const cM = api.response.match(/"count"\s*:\s*(\d+)/i);
      if (cM) api.recordCount = parseInt(cM[1]);
      else {
        const iM = api.response.match(/"items"\s*:\s*\[([^\]]*)\]/i);
        if (iM) api.recordCount = iM[1].trim() ? (iM[1].match(/\{/g) || []).length : 0;
        else api.recordCount = null;
      }
    } else api.recordCount = null;
  });

  const blankApis = WS.apis.filter(api => {
    if (api.status !== 200 || !api.response) return false;
    const r = api.response.trim();
    return r === '[]' || r === '{}' || /\"count\"\s*:\s*0\b/i.test(r) || /\"items\"\s*:\s*\[\s*\]/i.test(r);
  }).map(api => ({ name: api.name, endpoint: api.endpoint || 'Unknown', status: api.status, ms: api.ms, blankReason: 'Empty or zero-count response', recommendation: 'Verify query criteria and that records exist.' }));

  const loggerGaps = [];
  for (const t in WS.threadApiStates) {
    const st = WS.threadApiStates[t];
    loggerGaps.push({ type: 'Missing API Response Logger', description: `API "${st.name}" on thread "${t}" started but no response logged.`, recommendation: 'Add response logger in API client fallback block.' });
  }
  if (WS.dbStarts > WS.dbEnds + 2) loggerGaps.push({ type: 'Incomplete Database Logging', description: 'Multiple queries started without logged row counts.', recommendation: 'Enable SQL performance logging.' });

  let score = 100;
  const errPct = WS.totalLines ? (WS.exceptions.length / WS.totalLines) : 0;
  score -= Math.min(40, Math.round(errPct * 200));
  score -= Math.min(10, WS.warnings.length * 2);
  score -= Math.min(25, WS.apis.filter(a => a.status >= 400 || a.ms > 5000).length * 12);
  score -= Math.min(15, WS.apis.filter(a => a.ms > 2000 && a.status < 400).length * 8);
  score -= Math.min(20, WS.sqlIssues.filter(s => s.code !== 'JSON_KEY_MISSING').length * 10);
  score -= Math.min(25, blankApis.length * 5);
  score -= Math.min(15, loggerGaps.length * 3);
  const healthScore = Math.max(0, score);

  return {
    apis: WS.apis,
    exceptions: WS.exceptions,
    sqlIssues: WS.sqlIssues,
    warnings: WS.warnings,
    blankApis,
    logCounts: WS.logCounts,
    totalLines: WS.totalLines,
    logType: WS.logType,
    module: WS.module,
    users: [...WS.users],
    screen: WS.screen,
    transaction: WS.transaction,
    healthScore,
    loggerGaps,
    firstTimestamp: WS.firstTimestamp,
    lastTimestamp: WS.lastTimestamp,
    timeline: WS.timeline.slice(0, 10000), // cap for transfer
  };
}

// ─── Main message handler ─────────────────────────────────────────────────────
self.onmessage = function (ev) {
  const { type, text, chunkIndex, totalChunks, isLast } = ev.data;

  if (type === 'CHUNK') {
    processChunk(text, isLast);
    self.postMessage({
      type: 'CHUNK_RESULT',
      chunkIndex,
      totalChunks,
      isLast,
      stats: {
        totalLines: WS.totalLines,
        logCounts:  { ...WS.logCounts },
        apiCount:   WS.apis.length,
        errorCount: WS.exceptions.length,
        warnCount:  WS.warnings.length,
        sqlCount:   WS.sqlIssues.length,
        logType:    WS.logType,
      },
      newApis:      WS.apis.slice(-50),
      newExceptions: WS.exceptions.slice(-20),
    });
    if (isLast) {
      const result = finalizeState();
      self.postMessage({ type: 'COMPLETE', result });
    }
  }

  if (type === 'RESET') {
    Object.assign(WS, {
      currentEntry: null, entryId: 0, lineTail: '',
      apis: [], exceptions: [], sqlIssues: [], warnings: [], timeline: [],
      logCounts: { FATAL: 0, ERROR: 0, WARN: 0, INFO: 0, DEBUG: 0, TRACE: 0 },
      totalLines: 0, threadContexts: {}, threadLastTimes: {}, threadApiStates: {},
      dbStarts: 0, dbEnds: 0,
      logTypeHints: { flexi: 0, spring: 0, python: 0, node: 0, log4j: 0 },
      logType: 'Generic', firstTimestamp: null, lastTimestamp: null,
      users: new Set(), screen: null, transaction: null, module: null, moduleScores: {},
    });
  }
};
