/**
 * LogRadar Local Server
 * Serves the static web app AND provides a /api/open-in-editor endpoint
 * that saves script code to a temp file and launches it in a chosen editor.
 *
 * Usage: node logradar-server.js [port]
 * Default port: 9090
 */

'use strict';

const http       = require('http');
const fs         = require('fs');
const path       = require('path');
const os         = require('os');
const { exec }   = require('child_process');

const PORT       = parseInt(process.argv[2] || '9090', 10);
const PUBLIC_DIR = path.resolve(__dirname);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css' : 'text/css; charset=utf-8',
  '.js'  : 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png' : 'image/png',
  '.jpg' : 'image/jpeg',
  '.gif' : 'image/gif',
  '.svg' : 'image/svg+xml',
  '.log' : 'text/plain; charset=utf-8',
  '.txt' : 'text/plain; charset=utf-8',
};

/* ---------- Editor registry (Windows paths) -------------------------------- */
const EDITORS = {
  notepad:   { label: 'Notepad',    cmd: 'notepad.exe' },
  notepadpp: { label: 'Notepad++',  cmd: '"C:\\Program Files\\Notepad++\\notepad++.exe"', fallback: '"C:\\Program Files (x86)\\Notepad++\\notepad++.exe"' },
  vscode:    { label: 'VS Code',    cmd: 'code' },
  wordpad:   { label: 'WordPad',    cmd: 'write.exe' },
};

/* ---------- Helpers -------------------------------------------------------- */
function sanitizeFilename(str) {
  return String(str || 'script').replace(/[^a-zA-Z0-9_\-]/g, '_').substring(0, 64);
}

function corsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch (e) { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

/* ---------- API: /api/open-in-editor -------------------------------------- */
async function handleOpenInEditor(req, res) {
  let payload;
  try {
    payload = await readBody(req);
  } catch (e) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'Invalid request body' }));
    return;
  }

  const { code = '', fieldName = 'field', eventName = 'script', editor = 'notepad' } = payload;
  const fname   = `LogRadar_${sanitizeFilename(fieldName)}_${sanitizeFilename(eventName)}.js`;
  const tmpPath = path.join(os.tmpdir(), fname);

  // Write code to temp file
  try {
    fs.writeFileSync(tmpPath, code, 'utf8');
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'Failed to write temp file: ' + err.message }));
    return;
  }

  const editorConfig = EDITORS[editor] || EDITORS.notepad;
  const openCmd      = `${editorConfig.cmd} "${tmpPath}"`;

  exec(openCmd, (err) => {
    if (err && editorConfig.fallback) {
      // Try fallback path (e.g. Notepad++ in x86)
      const fallbackCmd = `${editorConfig.fallback} "${tmpPath}"`;
      exec(fallbackCmd, (err2) => {
        if (err2) {
          // Ultimate fallback: notepad
          exec(`notepad.exe "${tmpPath}"`);
        }
      });
    }
  });

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true, tmpPath, editor: editorConfig.label }));
}

/* ---------- API: /api/ping ------------------------------------------------ */
function handlePing(res) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true, server: 'logradar-local', version: '1.0' }));
}

/* ---------- Static file server -------------------------------------------- */
function handleStatic(req, res) {
  let safeUrl = req.url.split('?')[0];
  if (safeUrl === '/') safeUrl = '/index.html';

  const filePath = path.join(PUBLIC_DIR, safeUrl);

  // Prevent directory traversal
  if (!filePath.startsWith(path.normalize(PUBLIC_DIR))) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(err.code === 'ENOENT' ? 404 : 500);
      res.end(err.code === 'ENOENT' ? 'Not Found' : 'Server Error');
      return;
    }
    const ext         = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

/* ---------- Main router ---------------------------------------------------- */
const server = http.createServer(async (req, res) => {
  corsHeaders(res);

  // Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const pathname = req.url.split('?')[0];

  if (pathname === '/api/ping') {
    return handlePing(res);
  }

  if (pathname === '/api/open-in-editor' && req.method === 'POST') {
    return await handleOpenInEditor(req, res);
  }

  handleStatic(req, res);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════╗');
  console.log(`  ║  LogRadar Local Server running on port ${PORT}  ║`);
  console.log('  ║  http://localhost:' + PORT + '/                       ║');
  console.log('  ╚══════════════════════════════════════════════╝');
  console.log('');
  console.log('  Endpoints:');
  console.log('    GET  /             → LogRadar UI');
  console.log('    POST /api/open-in-editor  → Open script in editor');
  console.log('    GET  /api/ping     → Health check');
  console.log('');
});
