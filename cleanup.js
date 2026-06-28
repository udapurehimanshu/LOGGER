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

function cleanupJs() {
  let js = fs.readFileSync('app.js', 'utf8');

  // Remove handleScreenSelect
  js = js.replace(/function handleScreenSelect\(file\) \{[\s\S]*?\}\s*function refreshCodeReviewerView\(\)/, 'function refreshCodeReviewerView()');

  // Remove showScreenLoadingUI
  js = js.replace(/function showScreenLoadingUI\(filename\) \{[\s\S]*?\}\s*(?=\/\/)/, '');

  // Remove getActiveScreenDefinition
  js = js.replace(/function getActiveScreenDefinition\(\) \{[\s\S]*?\}\s*function refreshCodeReviewerView\(\) \{/, 'function refreshCodeReviewerView() {');

  // Remove refreshCodeReviewerView
  js = js.replace(/function refreshCodeReviewerView\(\) \{[\s\S]*?\}\s*function initCodeReviewer\(\) \{/, 'function initCodeReviewer() {');

  // Remove initCodeReviewer
  js = js.replace(/function initCodeReviewer\(\) \{[\s\S]*?\}\s*(?=\/\/ ───)/, '');

  // Remove upload-screen-btn listeners
  js = js.replace(/\/\/ Screen JSON upload[\s\S]*?e\.target\.value = '';\s*\n\s*\});/, '');

  // Remove initCodeReviewer calls
  js = js.replace(/initCodeReviewer\(\);/g, '');

  // Remove refreshCodeReviewerView calls
  js = js.replace(/refreshCodeReviewerView\(\);/g, '');

  // Remove AI Code Review commands
  js = js.replace(/\/\/ --- New Code Reviewer & Screen Explorer commands ---[\s\S]*?(?=if \(\/slow|latency|performance\/i\.test\(q\)\))/m, '');

  fs.writeFileSync('app.js', js);
  console.log("Cleaned up app.js");
}

cleanupHtml();
cleanupJs();
