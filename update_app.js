const fs = require('fs');
let code = fs.readFileSync('app.js', 'utf8');

// 1. Remove const SCREEN_SCRIPTS = { ... };
code = code.replace(/const SCREEN_SCRIPTS = \{[\s\S]*?function getActiveScreenDefinition\(\) \{/m, 'function getActiveScreenDefinition() {');

// 2. Rewrite getActiveScreenDefinition
code = code.replace(/function getActiveScreenDefinition\(\) \{[\s\S]*?function refreshCodeReviewerView/m, 
`function getActiveScreenDefinition() {
  return STATE.screenDefinition || null;
}

function refreshCodeReviewerView`);

// 3. Replace sData assignment in generateAIAnswer
code = code.replace(/const sData = SCREEN_SCRIPTS\[scr\] \|\| SCREEN_SCRIPTS\['TASK_SCREEN_11'\];/g, 
`const sData = getActiveScreenDefinition();
    if (!sData) return '⚠️ No screen definition loaded. Please upload a Screen JSON file.';`);

// 4. Update runScreenDebuggerAnalysis
code = code.replace(/const matchedKey = Object\.keys\(SCREEN_SCRIPTS\)\.find\([\s\S]*?isSimulated = true;\s*\}/m, '');

// Save changes
fs.writeFileSync('app.js', code);
console.log("Updated app.js successfully");
