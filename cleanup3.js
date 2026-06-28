const fs = require('fs');

function cleanupHtml() {
  let html = fs.readFileSync('index.html', 'utf8');

  // Remove upload-screen-btn block
  html = html.replace(/<button class="upload-btn-sidebar" id="upload-screen-btn"[\s\S]*?<div class="sidebar-file-name" id="sidebar-screen-name">No Screen JSON loaded<\/div>/, '');

  // Remove nav-codereview
  html = html.replace(/<button class="nav-item" data-view="codereview" id="nav-codereview">[\s\S]*?<\/button>\s*(<button class="nav-item" data-view="debugger" id="nav-debugger">)/, '$1');

  // Remove view-codereview
  html = html.replace(/<div class="view" id="view-codereview">[\s\S]*?<!-- ═══════════ SCREEN DEBUGGER VIEW ═══════════ -->/, '<!-- ═══════════ SCREEN DEBUGGER VIEW ═══════════ -->');

  // Also remove code reviewer mention in header or paragraphs
  html = html.replace(/Upload a log file or select a screen in the left dropdown to reconstruct the screen metadata, flow, and field inventories\./g, '');
  
  fs.writeFileSync('index.html', html);
  console.log("Cleaned up index.html");
}

cleanupHtml();
