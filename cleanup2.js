const fs = require('fs');

function cleanupJs() {
  let js = fs.readFileSync('app.js', 'utf8');

  // Remove handleScreenSelect
  js = js.replace(/function handleScreenSelect\(file\) \{[\s\S]*?\}\s*function runScreenDebuggerAnalysis\(\) \{/, 'function runScreenDebuggerAnalysis() {');

  js = js.replace(/function refreshCodeReviewerView\(\) \{[\s\S]*?\n\}\s*\n/, '\n');
  js = js.replace(/function initCodeReviewer\(\) \{[\s\S]*?\n\}\s*\n/, '\n');
  js = js.replace(/function getActiveScreenDefinition\(\) \{[\s\S]*?\n\}\s*\n/, '\n');

  // Remove upload-screen-btn listeners
  js = js.replace(/\/\/ Screen JSON upload[\s\S]*?e\.target\.value = '';\s*\n\s*\}\);/, '');

  // Remove initCodeReviewer calls
  js = js.replace(/initCodeReviewer\(\);/g, '');

  // Remove refreshCodeReviewerView calls
  js = js.replace(/refreshCodeReviewerView\(\);/g, '');

  // Remove AI Code Review commands
  js = js.replace(/\/\/ --- New Code Reviewer & Screen Explorer commands ---[\s\S]*?(?=if \(\/slow\|latency\|performance\/i\.test\(q\)\))/m, '');

  js = js.replace(/let screenDef = STATE\.screenDefinition;\s*let isSimulated = false;\s*if \(!screenDef\) \{[\s\S]*?return;\s*\}/m, 'return; // Screen Debugger removed');

  fs.writeFileSync('app.js', js);
  console.log("Cleaned up app.js");
}

cleanupJs();
