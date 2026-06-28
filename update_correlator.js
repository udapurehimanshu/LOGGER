const fs = require('fs');
let code = fs.readFileSync('app.js', 'utf8');

// 1. Inject deepFindKey helper before handleScreenSelect
const deepSearchCode = `
function deepFindKey(obj, keyToFind) {
  if (typeof obj !== 'object' || obj === null) return null;
  if (obj[keyToFind]) return obj[keyToFind];
  for (let key in obj) {
    const res = deepFindKey(obj[key], keyToFind);
    if (res) return res;
  }
  return null;
}

function handleScreenSelect`;

code = code.replace(/function handleScreenSelect/, deepSearchCode);

// 2. Update the parsing block inside handleScreenSelect
const parseBlockRepl = `
      let data;
      try {
        data = JSON.parse(ev.target.result);
        const deepFields = deepFindKey(data, 'fields');
        const deepWS = deepFindKey(data, 'webservices');
        
        if (!data.screenName && !data.title && !deepFields) {
           data = { screenName: file.name, title: file.name, rawCode: ev.target.result };
        } else {
           if (!data.fields && deepFields) data.fields = deepFields;
           if (!data.webservices && deepWS) data.webservices = deepWS;
           if (!data.screenName) data.screenName = file.name;
        }
      } catch (err) {
        // Not a JSON file, treat as raw code
        data = { screenName: file.name, title: file.name, rawCode: ev.target.result };
      }
`;
code = code.replace(/let data;\s*try \{[\s\S]*?rawCode: ev\.target\.result \};\s*\}/, parseBlockRepl.trim());


// 3. Rewrite runScreenDebuggerAnalysis HTML generation
// We'll replace the old "Screen Code Snapshot" logic added in update_logic3.js
// Wait, actually I can just overwrite the whole `let analysisHtml = ''; ...` block down to `$('dbg-analysis-panel').innerHTML = analysisHtml;`

const newRenderer = `
  let analysisHtml = '';

  // 1. RAW CODE DISPLAY (Fallback)
  if (screenDef.rawCode) {
    analysisHtml += \`
      <div class="dbg-copilot-section">
        <div class="dbg-copilot-title" style="color:#38BDF8;">
          <span>💻</span> UPLOADED CODE (RAW)
        </div>
        <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
          Raw code from \${STATE.currentScreenFile || 'the uploaded file'}.
        </div>
        <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:4px 0 0 0; border:1px solid rgba(255,255,255,0.06);">\${escHtml(screenDef.rawCode)}</pre>
      </div>
    \`;
  }

  // 2. DETAILED FIELD AND WEBSERVICE CORRELATION
  if (screenDef.fields) {
    const errorPatterns = ["nullpointer", "exception", "ora-", "targeterror", "timeout", "http 5", "http 4", "error"];
    
    let screenCodeHtml = '<div style="display:flex; flex-direction:column; gap:16px;">';
    for (const [fieldName, events] of Object.entries(screenDef.fields)) {
      let fieldHasError = false;
      let errorReason = "";
      
      // Check if log contains this field near an error
      const fieldRegex = new RegExp(fieldName, 'i');
      if (fieldRegex.test(logText)) {
        for (const ep of errorPatterns) {
          if (logText.toLowerCase().includes(ep)) {
            fieldHasError = true;
            errorReason = \`The log file indicates a potential \${ep.toUpperCase()} near execution of this field.\`;
            break;
          }
        }
      }

      let eventsHtml = '';
      let associatedWS = null;

      for (const [evName, ev] of Object.entries(events)) {
         if (ev.code) {
           eventsHtml += \`
             <div style="margin-top:12px;">
               <strong style="color:#818CF8; font-size:12px;">\${escHtml(evName)} Code:</strong>
               <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:4px 0 0 0; border:1px solid rgba(255,255,255,0.06);">\${escHtml(ev.code)}</pre>
             </div>
           \`;
           
           // Heuristic: Does this code call a webservice?
           if (screenDef.webservices) {
             for (const wsName of Object.keys(screenDef.webservices)) {
               if (ev.code.includes(wsName)) {
                 associatedWS = { name: wsName, data: screenDef.webservices[wsName] };
               }
             }
           }
         }
      }

      let wsHtml = '';
      if (associatedWS) {
        const ws = associatedWS.data;
        wsHtml += \`
          <div style="margin-top:12px; background:rgba(0,0,0,0.2); padding:10px; border-radius:6px; border:1px solid rgba(245, 158, 11, 0.2);">
            <div style="font-size:12px; font-weight:bold; color:#F59E0B; margin-bottom:8px;">🔗 Associated WebService: \${escHtml(associatedWS.name)}</div>
            <div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>URL:</strong> \${escHtml(ws.request || ws.url || 'N/A')}</div>
        \`;
        if (ws.requestMap || ws.body) {
           wsHtml += \`<div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Request Body / Map:</strong> <pre style="display:inline; background:#111827; padding:2px 4px; border-radius:4px;">\${escHtml(JSON.stringify(ws.requestMap || ws.body))}</pre></div>\`;
        }
        if (ws.responseMap || ws.response) {
           wsHtml += \`<div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Response Map:</strong> <pre style="display:inline; background:#111827; padding:2px 4px; border-radius:4px;">\${escHtml(JSON.stringify(ws.responseMap || ws.response))}</pre></div>\`;
        }
        if (ws.columnMap) {
           wsHtml += \`<div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Column Map:</strong> <pre style="display:inline; background:#111827; padding:2px 4px; border-radius:4px;">\${escHtml(JSON.stringify(ws.columnMap))}</pre></div>\`;
        }
        wsHtml += \`</div>\`;
        
        // If the WS is found in the log next to an error, mark field as error
        if (!fieldHasError && new RegExp(associatedWS.name, 'i').test(logText)) {
          for (const ep of errorPatterns) {
            if (logText.toLowerCase().includes(ep)) {
               fieldHasError = true;
               errorReason = \`The log file indicates a potential API failure (\${ep.toUpperCase()}) during the execution of \${associatedWS.name}.\`;
               break;
            }
          }
        }
      }

      if (eventsHtml || wsHtml) {
         screenCodeHtml += \`
           <div style="background:\${fieldHasError ? 'rgba(239, 68, 68, 0.05)' : 'rgba(255,255,255,0.02)'}; padding:16px; border:1px solid \${fieldHasError ? 'rgba(239, 68, 68, 0.3)' : 'rgba(255,255,255,0.04)'}; border-radius:8px;">
             <div style="display:flex; justify-content:space-between; align-items:center;">
               <h4 style="margin:0; color:\${fieldHasError ? '#EF4444' : '#38BDF8'}; font-size:14px; display:flex; align-items:center; gap:8px;">
                 \${fieldHasError ? '🔴' : '✅'} Field: \${escHtml(fieldName)}
               </h4>
             </div>
             \${fieldHasError ? \`<div style="font-size:12px; color:#FCA5A5; margin-top:8px; padding:8px; background:rgba(239, 68, 68, 0.1); border-radius:4px;"><strong>🚨 Issue Detected:</strong> \${errorReason}<br><br><strong>Debugging Step:</strong> Review the code and API payload below. Add <code>logger.error()</code> inside the Catch block or before the API call to trace the exact mismatch.</div>\` : ''}
             \${wsHtml}
             \${eventsHtml}
           </div>
         \`;
      }
    }
    screenCodeHtml += '</div>';

    analysisHtml += \`
      <div class="dbg-copilot-section">
        <div class="dbg-copilot-title" style="color:#38BDF8; font-size:14px; border-bottom:1px solid rgba(56, 189, 248, 0.2); padding-bottom:8px; margin-bottom:16px;">
          <span>🧠</span> UPLOADED SCREEN CODE & API CORRELATION
        </div>
        <div style="font-size:13px; color:var(--text-muted); margin-bottom:16px; line-height:1.5;">
          The AI has parsed your uploaded code file and successfully extracted the fields, their exact <code>OnExit</code> / <code>OnFocus</code> code, and any embedded WebService structures. 
          It then cross-referenced these against the <strong>uploaded log file</strong> to detect which field crashed.
        </div>
        \${screenCodeHtml}
      </div>
    \`;
  }

  $('dbg-analysis-panel').innerHTML = analysisHtml;
`;

// Replace from `let analysisHtml = '';` up to `$('dbg-analysis-panel').innerHTML = analysisHtml;`
code = code.replace(/let analysisHtml = '';[\s\S]*?\$\('dbg-analysis-panel'\)\.innerHTML = analysisHtml;/, newRenderer.trim());

fs.writeFileSync('app.js', code);
console.log('App.js updated with advanced parser and correlator');
