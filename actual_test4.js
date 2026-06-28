const fs = require('fs');
const vm = require('vm');

const mockDOM = {};
global.document = {
  addEventListener: () => {},
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

global.STATE = {
  parsed: [
    { message: "Executing ORG_WEBSERVICE" },
    { message: "HTTP 500 Error occurred near ORG_CODE" },
    { message: "NullPointerException detected in ITEM field" }
  ],
  analysis: { apis: [] }, // This is truthy!
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

global.window = {};
global.localStorage = { getItem: () => null, setItem: () => {} };
global.escHtml = (str) => {
   if (typeof str !== 'string') return String(str);
   return str.replace(/</g, '&lt;').replace(/>/g, '&gt;');
};
global.isLogRelatedToScreen = () => true;

const appCode = fs.readFileSync('app.js', 'utf8');

vm.runInThisContext(appCode);

try {
  runScreenDebuggerAnalysis();
  console.log("SUCCESS: runScreenDebuggerAnalysis executed without throwing errors.");
  console.log("--- GENERATED HTML SNIPPET ---");
  const html = global.document.getElementById('dbg-analysis-panel').innerHTML;
  
  if (html.includes("SCREEN HEALTH SCORE")) {
    console.log("SUCCESS: Health Score rendered.");
  }
  if (html.includes("DEVELOPER INVESTIGATION PATH")) {
    console.log("SUCCESS: Investigation path rendered.");
  }
  if (html.includes("Debugging Assistant")) {
    console.log("SUCCESS: Debugging assistant injected.");
  }
} catch(e) {
  console.error("ERROR running runScreenDebuggerAnalysis:");
  console.error(e);
}
