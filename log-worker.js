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
  logTypeHints: { flexi: 0, spring: 0, python: 0, node: 0, log4j: 0, oracle: 0, tomcat: 0, java: 0 },
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
const RE_M1_FLEXI = /^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\[(.*?)\]\s+(\S+)\s+-\s+(.+)$/i;
const RE_M1_FLEXI_B = /^\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s*\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+\[([^\]]+)\]\[(.*?)\]\s+(.+)$/i;
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
  m = line.match(RE_M1_FLEXI);
  if (m) return { timestamp: m[2], thread: m[4], level: m[1].toUpperCase(), source: m[5], message: m[6] };
  m = line.match(RE_M1_FLEXI_B);
  if (m) return { timestamp: m[2], thread: m[4], level: m[1].toUpperCase(), source: 'Unknown', message: m[5] };
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
// ─── API Extraction (stateful state-machine) ──────────────────────────────────
function processApiLine(e) {
  const thread = e.thread || 'main';
  const msg = e.message;
  const timestamp = e.timestamp || '';
  
  if (!WS.threadApiStates[thread]) {
     WS.threadApiStates[thread] = {
        state: 'IDLE',
        api: null,
        jsonBuffer: '',
        braceCount: 0,
     };
  }
  const tState = WS.threadApiStates[thread];

  const lines = msg.split('\n');
  for (let line of lines) {
     line = line.trim();
     if (!line) continue;

     // ─── State: RESPONSE_JSON (collecting JSON text) ───
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
           
           finalizeAndPushApi(tState.api);
           tState.state = 'IDLE';
           tState.api = null;
           tState.jsonBuffer = '';
           tState.braceCount = 0;
        }
        continue;
     }

     // ─── Detect API Start patterns ───
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
           finalizeAndPushApi(tState.api);
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

     if (line.includes('runWebService') && line.includes('result') && !tState.api) {
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

     // ─── Parse metadata inside session ───
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
           
           finalizeAndPushApi(tState.api);
           tState.state = 'IDLE';
           tState.api = null;
           tState.jsonBuffer = '';
           tState.braceCount = 0;
        }
     }
  }
}

function finalizeAndPushApi(api) {
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

  WS.apis.push(api);
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
  if (msgL.includes('oracle') || msgL.includes('ora-') || msgL.includes('jdbc.driver')) WS.logTypeHints.oracle++;
  if (msgL.includes('tomcat') || msgL.includes('catalina') || msgL.includes('org.apache.catalina')) WS.logTypeHints.tomcat++;
  if (msgL.includes('java.lang') || msgL.includes('exception') || msgL.includes('nullpointerexception')) WS.logTypeHints.java++;

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
  for (const t in WS.threadApiStates) {
    if (WS.threadApiStates[t].api) {
      finalizeAndPushApi(WS.threadApiStates[t].api);
      WS.threadApiStates[t].api = null;
    }
  }

  // Log type
  const h = WS.logTypeHints;
  if (h.flexi > 0) WS.logType = 'Flexi Runtime';
  else if (h.spring > 0) WS.logType = 'Spring Boot';
  else if (h.tomcat > 0) WS.logType = 'Apache Tomcat';
  else if (h.oracle > 0) WS.logType = 'Oracle Database';
  else if (h.java > 0)   WS.logType = 'Java Application';
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
    
    // Auto-fill query params from URL if not already done
    if (api.endpoint && api.endpoint.includes('?')) {
      const qIdx = api.endpoint.indexOf('?');
      api.queryParams = api.endpoint.substring(qIdx + 1);
    }

    if (api.response) {
      const cM = api.response.match(/"count"\s*:\s*(\d+)/i) || api.response.match(/"result_count"\s*:\s*(\d+)/i);
      if (cM) api.recordCount = parseInt(cM[1]);
      else {
        const iM = api.response.match(/"items"\s*:\s*\[([^\]]*)\]/i);
        if (iM) api.recordCount = iM[1].trim() ? (iM[1].match(/\{/g) || []).length : 0;
        else api.recordCount = null;
      }
    } else api.recordCount = null;

    if (!api.businessResult) {
      if (api.status >= 400) { api.businessResult = `Failed (HTTP ${api.status})`; }
      else if (api.response) {
        const r = api.response;
        if (r.includes('"success":false') || r.includes('"valid":false')) api.businessResult = 'Business Validation Failure';
        else if (r.trim() === '[]' || r.trim() === '{}' || api.recordCount === 0 || /\"count\"\s*:\s*0\b/i.test(r) || /\"items\"\s*:\s*\[\s*\]/i.test(r)) api.businessResult = 'Blank Response';
        else api.businessResult = 'Healthy';
      } else api.businessResult = 'Healthy';
    }
    if (!api.endpoint && api.response) {
      const hM = api.response.match(/"href"\s*:\s*"([^"]+)"/i);
      if (hM) api.endpoint = hM[1];
    }

    // Health Classification
    let health = 'Healthy';
    const isTimeout = api.status === 504 || api.ms >= 30000 || (api.response && api.response.toLowerCase().includes('timeout'));
    if (isTimeout) {
      health = 'Timeout';
    } else if (api.status >= 400) {
      health = 'Failed';
    } else if (api.retryCount > 0) {
      health = 'Retry';
    } else if (api.businessResult === 'Blank Response') {
      health = 'Blank Response';
    } else if (api.ms > 2000) {
      health = 'Slow';
    } else {
      health = 'Healthy';
    }
    api.health = health;
  });

  const blankApis = WS.apis.filter(api => api.health === 'Blank Response').map(api => {
    let reason = 'Empty response body';
    let rec = 'Verify query criteria. Ensure the underlying database contains active records for this entity.';
    if (api.response) {
      const r = api.response.trim();
      if (r === '[]' || r === '{}') {
        reason = 'Empty response body';
      } else if (/\"count\"\s*:\s*0\b/i.test(r) && /\"items\"\s*:\s*\[\s*\]/i.test(r)) {
        reason = 'Empty items list with count 0';
        rec = 'Query executed successfully but returned zero results. Check if search filters are too restrictive.';
      } else if (/\"count\"\s*:\s*0\b/i.test(r)) {
        reason = 'Response count field is 0';
        rec = 'Verify if search filter fields (like organization code or item reference) match valid active records.';
      } else if (/\"items\"\s*:\s*\[\s*\]/i.test(r)) {
        reason = 'Items array is empty';
        rec = 'Check query parameter values. If user has data-level restrictions, Oracle may return 200 with an empty list.';
      }
    }
    return {
      name: api.name,
      endpoint: api.endpoint || 'Unknown',
      status: api.status,
      ms: api.ms,
      blankReason: reason,
      recommendation: rec,
      logIndex: api.logIndex
    };
  });

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
      logTypeHints: { flexi: 0, spring: 0, python: 0, node: 0, log4j: 0, oracle: 0, tomcat: 0, java: 0 },
      logType: 'Generic', firstTimestamp: null, lastTimestamp: null,
      users: new Set(), screen: null, transaction: null, module: null, moduleScores: {},
    });
  }
};
