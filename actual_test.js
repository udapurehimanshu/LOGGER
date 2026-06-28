const fs = require('fs');

// Mock the DOM
const mockDOM = {};
global.document = {
  getElementById: (id) => {
    if (!mockDOM[id]) {
      mockDOM[id] = { 
        innerHTML: '', 
        textContent: '', 
        style: {},
        classList: { add: () => {}, remove: () => {} }
      };
    }
    return mockDOM[id];
  }
};

// Mock STATE
global.STATE = {
  parsed: [
    { message: "Executing ORG_WEBSERVICE" },
    { message: "HTTP 500 Error occurred near ORG_CODE" },
    { message: "NullPointerException detected in ITEM field" }
  ],
  analysis: { apis: [] },
  filterByScreen: true,
  screenDefinition: {
    screenName: "WO_COMPLETION",
    fields: {
      "ORG_CODE": { "OnExit": { code: "flexi.invokeWebService('ORG_WEBSERVICE'); logger.debug('hello');" } },
      "ITEM": { "OnFocus": { code: "// no logic" } }
    },
    webservices: {
      "ORG_WEBSERVICE": { request: "http://api.com/org", response: "{ status: 'ok' }" }
    }
  },
  currentScreenFile: "WO_COMPLETION.json"
};

// Mock eschtml
global.escHtml = (str) => {
   if (typeof str !== 'string') return String(str);
   return str.replace(/</g, '&lt;').replace(/>/g, '&gt;');
};

global.isLogRelatedToScreen = () => true;

// Load app.js and execute it
const appCode = fs.readFileSync('app.js', 'utf8').replace(/document\.addEventListener/g, '// document.addEventListener');

try {
  eval(appCode);
  runScreenDebuggerAnalysis();
  console.log("SUCCESS: runScreenDebuggerAnalysis executed without throwing errors.");
  console.log("--- GENERATED HTML SNIPPET (First 500 chars) ---");
  console.log(global.document.getElementById('dbg-analysis-panel').innerHTML.substring(0, 500) + '...');
} catch(e) {
  console.error("ERROR running runScreenDebuggerAnalysis:");
  console.error(e);
}
